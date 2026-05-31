#!/usr/bin/env python3
"""
Q4-completo da banca — captura p_BERT e p_CatBoost por URL e faz o sweep de
pesos da cascata e da zona de incerteza.

Contexto: a cascata de producao decide por BERT sozinho, exceto quando
LOWER < p_BERT < UPPER (zona de incerteza), caso em que combina:
    p_final = W * p_BERT + (1 - W) * p_CatBoost
Os valores de producao sao W=0,6 e zona 0,15/0,85 (app.py). A rodada formal
NAO salvou p_BERT e p_CatBoost por URL, entao nao dava para estudar a
sensibilidade desses parametros. Este script recaptura ambos e varre os pesos.

Decisao de escopo (banca): p_CatBoost so e calculado para as URLs que caem na
zona 0,15-0,85 (onde o CatBoost de fato pesa). Fora da zona, p_final = p_BERT.

REQUER: torch, transformers, catboost, dnspython, python-whois, httpx (todos
ja presentes). Roda em CPU, SEM GPU. WHOIS via cache; DNS/redirects ao vivo
apenas no subconjunto da zona.

Uso:
    python q4_cascata_sweep.py
"""
import asyncio
import csv
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

import torch

BASE = Path(__file__).resolve().parent.parent
API_DIR = BASE / "phishing-api"
MODEL_DIR = API_DIR / "model"
LISTA = Path(__file__).resolve().parent / "lista_validacao.csv"
OUT_DIR = Path(__file__).resolve().parent / "resultados"

# Constantes de producao (espelham app.py)
PHISHING_THRESHOLD = 0.65
ZONA_LOWER = 0.15
ZONA_UPPER = 0.85
PESO_PROD = 0.6
MAX_LENGTH = 128

# Permite importar server_features e usar o whois_cache que producao usa.
sys.path.insert(0, str(API_DIR))
os.environ.setdefault("WHOIS_CACHE_PATH", str(MODEL_DIR / "whois_cache.json"))

ENCURTADORES = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"}


def client_features(url):
    """11 client features, identicas ao que a extensao envia (ver ClientFeatures)."""
    p = urlparse(url if "://" in url else "http://" + url)
    host = p.hostname or ""
    query = p.query or ""
    return [
        len(url),                                   # length
        len(host),                                  # dom_length
        url.count("."),                             # dot
        url.count("-"),                             # hyphen
        url.count("/"),                             # slash
        url.count("@"),                             # at
        len([x for x in query.split("&") if x]),    # params
        1 if host.lower() in ENCURTADORES else 0,   # shortened
        1 if p.scheme == "https" else 0,            # tls
        sum(host.lower().count(v) for v in "aeiou"),  # vowels_domain
        1 if "@" in url else 0,                     # email
    ]


def carregar_modelos():
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    from catboost import CatBoostClassifier

    tok = AutoTokenizer.from_pretrained(str(MODEL_DIR))
    bert = AutoModelForSequenceClassification.from_pretrained(str(MODEL_DIR))
    bert.eval()
    cb = CatBoostClassifier()
    cb.load_model(str(MODEL_DIR / "catboost_cascata.cbm"))
    return tok, bert, cb


def bert_prob(tok, bert, url):
    """P(phishing) do BERT sobre a URL crua — identico a _bert_predict."""
    inputs = tok(url, return_tensors="pt", truncation=True, max_length=MAX_LENGTH, padding=True)
    with torch.no_grad():
        logits = bert(**inputs).logits
        probs = torch.softmax(logits, dim=-1)
    return probs[0][1].item()


async def catboost_prob(cb, url, cfeat):
    """P(phishing) do CatBoost — vetor de 24 features na ordem do feature_columns.json,
    replicando os getattr/defaults de _catboost_predict (TLS/registrar/country/whois_privacy
    nunca existem no dataclass -> caem nos defaults, igual a producao)."""
    from server_features import extract_server_features

    sf = await extract_server_features(url)
    vetor = cfeat + [
        sf.redirects, sf.dom_age, sf.dom_expire, sf.mx_servers, sf.nameservers,
        sf.dom_spf, sf.dom_in_ip,
        getattr(sf, "tls_validity_days", -1),
        getattr(sf, "tls_san_count", -1),
        getattr(sf, "registrar", "unknown"),
        getattr(sf, "country_code", "unknown"),
        getattr(sf, "tls_issuer", "unknown"),
        getattr(sf, "whois_privacy", -1),
    ]
    proba = cb.predict_proba([vetor])
    return float(proba[0][1])


def metricas(y_true, y_score, thr=PHISHING_THRESHOLD):
    """TP/FP/TN/FN -> precision, recall, f1, fpr, accuracy, mcc."""
    tp = fp = tn = fn = 0
    for yt, ys in zip(y_true, y_score):
        pred = ys > thr
        if yt and pred:
            tp += 1
        elif yt and not pred:
            fn += 1
        elif not yt and pred:
            fp += 1
        else:
            tn += 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    den = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    mcc = ((tp * tn - fp * fn) / den) if den else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(f1, 4), "fpr": round(fpr, 4),
            "accuracy": round(acc, 4), "mcc": round(mcc, 4)}


def final_prob(p_bert, p_cat, w, lo, hi):
    """p_final da cascata para um dado peso/zona. p_cat=None -> fora da zona capturada."""
    if p_cat is not None and lo < p_bert < hi:
        return w * p_bert + (1 - w) * p_cat
    return p_bert


async def main():
    OUT_DIR.mkdir(exist_ok=True)
    print("Carregando modelos (BERT + CatBoost)...")
    tok, bert, cb = carregar_modelos()

    # Le a lista
    amostras = []
    with open(LISTA, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            amostras.append((row["url"], row["label"].strip().lower() == "phishing"))
    print(f"URLs na lista: {len(amostras)}")

    # 1) p_BERT para todas
    print("Rodando BERT em todas as URLs (CPU)...")
    registros = []
    for i, (url, is_phish) in enumerate(amostras):
        pb = bert_prob(tok, bert, url)
        registros.append({"url": url, "phishing": is_phish, "p_bert": pb, "p_cat": None})
        if (i + 1) % 250 == 0:
            print(f"  BERT {i + 1}/{len(amostras)}")

    # 2) p_CatBoost apenas na zona de incerteza
    zona = [r for r in registros if ZONA_LOWER < r["p_bert"] < ZONA_UPPER]
    print(f"URLs na zona {ZONA_LOWER}-{ZONA_UPPER}: {len(zona)} "
          f"(CatBoost + DNS/WHOIS/redirects ao vivo so nessas)")

    sem = asyncio.Semaphore(16)

    async def processa(r):
        async with sem:
            try:
                r["p_cat"] = await catboost_prob(cb, r["url"], client_features(r["url"]))
            except Exception as e:
                r["p_cat"] = None
                r["erro_cat"] = str(e)[:120]

    for j in range(0, len(zona), 50):
        await asyncio.gather(*(processa(r) for r in zona[j:j + 50]))
        print(f"  CatBoost {min(j + 50, len(zona))}/{len(zona)}")

    # 3) salva CSV por URL
    csv_path = OUT_DIR / "q4_probs_por_url.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "phishing", "p_bert", "p_cat", "in_zona"])
        for r in registros:
            in_zona = ZONA_LOWER < r["p_bert"] < ZONA_UPPER
            w.writerow([r["url"], int(r["phishing"]), round(r["p_bert"], 6),
                        ("" if r["p_cat"] is None else round(r["p_cat"], 6)), int(in_zona)])
    print(f"Salvo: {csv_path}")

    # 4) sweep de pesos e zona (zona <= produzida; nao da p/ ampliar alem de 0,15-0,85)
    y = [r["phishing"] for r in registros]
    cenarios = {}
    cenarios["bert_sozinho"] = metricas(y, [r["p_bert"] for r in registros])
    for w in (0.5, 0.6, 0.7):
        nome = f"cascata_W{w}_zona{ZONA_LOWER}-{ZONA_UPPER}"
        scores = [final_prob(r["p_bert"], r["p_cat"], w, ZONA_LOWER, ZONA_UPPER) for r in registros]
        cenarios[nome] = metricas(y, scores)
    # zona mais estreita (subconjunto da capturada), peso de producao
    for lo, hi in [(0.30, 0.70), (0.40, 0.60)]:
        nome = f"cascata_W{PESO_PROD}_zona{lo}-{hi}"
        scores = [final_prob(r["p_bert"], r["p_cat"], PESO_PROD, lo, hi) for r in registros]
        cenarios[nome] = metricas(y, scores)

    resumo = {
        "descricao": "Q4-completo: captura de p_BERT/p_CatBoost por URL e sweep de pesos/zona da cascata.",
        "gerado_em": "2026-05-31",
        "limiar_decisao": PHISHING_THRESHOLD,
        "n_urls": len(registros),
        "n_zona_incerteza": len(zona),
        "zona_capturada": [ZONA_LOWER, ZONA_UPPER],
        "peso_producao": PESO_PROD,
        "nota_escopo": ("p_CatBoost capturado so na zona 0,15-0,85; sweep de zona limitado a "
                        "subconjuntos dessa faixa. TLS/registrar/country/whois_privacy sao "
                        "constantes (default) tambem em producao."),
        "cenarios": cenarios,
    }
    json_path = OUT_DIR / "q4_cascata_sweep.json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(resumo, fh, indent=2, ensure_ascii=False)
    print(f"Salvo: {json_path}")

    print("\n=== Metricas por cenario (limiar %.2f) ===" % PHISHING_THRESHOLD)
    hdr = f"{'cenario':<34} {'F1':>7} {'FPR':>7} {'recall':>7} {'prec':>7} {'MCC':>7}"
    print(hdr)
    for nome, m in cenarios.items():
        print(f"{nome:<34} {m['f1']:>7.4f} {m['fpr']:>7.4f} {m['recall']:>7.4f} "
              f"{m['precision']:>7.4f} {m['mcc']:>7.4f}")


if __name__ == "__main__":
    asyncio.run(main())
