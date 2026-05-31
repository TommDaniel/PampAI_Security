# -*- coding: utf-8 -*-
"""Explicabilidade dos 3 modelos do TCC — execucao LOCAL na CPU.

Roda do inicio ao fim sem notebook/kernel (nao depende de Colab, nao cai sessao).
Salva cada figura em explicabilidade/figuras/ assim que fica pronta.

Uso:
    python explicabilidade/rodar_local.py

Modelos (ja no disco, exceto o de email que baixa do Hub):
  - DomURLs-BERT  -> phishing-api/model/            (SHAP de tokens + atencao)
  - DistilBERT    -> cybersectony/... (HuggingFace)  (SHAP de tokens + atencao)
  - CatBoost      -> phishing-api/model/catboost_cascata.cbm  (TreeSHAP)
"""
import os, json, gc, sys, time
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # backend nao-interativo: salva PNG de forma estavel
import matplotlib.pyplot as plt
import torch

# --------------------------------------------------------------------------
# Configuracao (caminhos LOCAIS)
# --------------------------------------------------------------------------
BASE        = Path(__file__).resolve().parent.parent          # .../TCC
MODEL_DIR   = BASE / "phishing-api" / "model"
DOMURLS_DIR = MODEL_DIR                                        # modelo deployado (vocab 32006)
CATBOOST_CBM      = MODEL_DIR / "catboost_cascata.cbm"
CATBOOST_CSV      = MODEL_DIR / "dataset_cascata_20k.csv"
FEATURE_COLS_JSON = MODEL_DIR / "feature_columns.json"
EMAIL_MODEL_ID    = "cybersectony/phishing-email-detection-distilbert_v2.4.1"

OUTPUT_DIR = Path(__file__).resolve().parent / "figuras"
OUTPUT_DIR.mkdir(exist_ok=True)

# CPU: limita avaliacoes do SHAP de texto p/ manter o tempo sob controle
MAX_LENGTH_URL   = 192
MAX_LENGTH_EMAIL = 256
SHAP_MAX_EVALS   = 300     # coalizoes do Partition explainer por exemplo
SHAP_BATCH       = 16
N_EXPLAIN_CB     = 2000    # subset p/ beeswarm do CatBoost
RANDOM_STATE     = 42

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

EXEMPLOS_URL = [
    ("[URL] https://www.google.com [WHOIS] unknown [EXTRA] length=24 tls=1", "LEGIT"),
    ("[URL] https://www.bb.com.br [WHOIS] unknown [EXTRA] length=22 tls=1",  "LEGIT"),
    ("[URL] http://192.168.1.1.login.xyz/steal [WHOIS] unknown [EXTRA] length=38 tls=0", "PHISH"),
    ("[URL] http://bb-seguranca.ml/acesso [WHOIS] unknown [EXTRA] length=32 tls=0",      "PHISH"),
    ("[URL] http://paypal-verify.xyz/account [WHOIS] unknown [EXTRA] length=35 tls=0",   "PHISH"),
    ("https://www.google.com",             "LEGIT"),
    ("http://192.168.1.1.login.xyz/steal", "PHISH"),
]
EXEMPLOS_EMAIL = [
    ("From: security@paypal-verify.com\n"
     "Subject: Your account has been suspended\n\n"
     "Dear customer, we detected unusual activity on your account. "
     "Click http://paypal-verify.xyz/account to verify your identity within 24 hours "
     "or your account will be permanently closed.", "PHISH"),
    ("From: noreply@github.com\n"
     "Subject: Your weekly digest\n\n"
     "Here is a summary of activity in your repositories this week. "
     "Thanks for using GitHub!", "LEGIT"),
]


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def savefig(name):
    path = OUTPUT_DIR / name
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    log(f"  salvo: {path.name}")


# --------------------------------------------------------------------------
# Helpers de transformer (SHAP de texto + atencao)
# --------------------------------------------------------------------------
def make_logit_fn(mdl, tok, max_length):
    """f(list[str]) -> logits (n, n_classes).

    Explicamos o LOGIT (nao a probabilidade softmax): perto da saturacao o softmax
    quase nao muda ao mascarar tokens, gerando atribuicoes ~0 ("+0"). O logit tem
    escala bem maior e produz contribuicoes por token legiveis.
    """
    def f(texts):
        texts = [str(t) for t in (texts.tolist() if hasattr(texts, "tolist") else texts)]
        enc = tok(texts, return_tensors="pt", padding=True,
                  truncation=True, max_length=max_length)
        enc = {k: v.to(device) for k, v in enc.items()}
        with torch.no_grad():
            logits = mdl(**enc).logits
        return logits.cpu().numpy()
    return f


def _limpar_token(t):
    """Remove marcadores de subword (## / Ġ) para legibilidade no rotulo."""
    t = str(t)
    if t.startswith("##"):
        return t[2:]
    return t.replace("Ġ", "").replace("Ċ", "")


def barra_tokens_limpa(values, tokens, titulo, fname, topk=15):
    """Barra horizontal limpa de contribuicao por token (sem dendrograma/+0)."""
    values = np.asarray(values, dtype=float)
    tokens = [_limpar_token(t) for t in tokens]
    absv = np.abs(values)
    vmax = absv.max() if absv.size else 0.0
    # mantem so tokens relevantes: top-k por |valor| e acima de 1% do maior
    cand = [j for j in np.argsort(absv)[::-1][:topk] if vmax > 0 and absv[j] >= 0.01 * vmax]
    if not cand:
        cand = list(np.argsort(absv)[::-1][:min(topk, len(values))])
    cand = sorted(cand, key=lambda j: values[j])  # ordena p/ exibir
    v = values[cand]
    labels = [tokens[j] if tokens[j].strip() else "·" for j in cand]
    colors = ["#ff0051" if x > 0 else "#008bfb" for x in v]

    plt.figure(figsize=(7.5, max(3, len(v) * 0.42)))
    plt.barh(range(len(v)), v, color=colors)
    plt.yticks(range(len(v)), labels, fontsize=9)
    plt.axvline(0, color="k", lw=0.8)
    span = max(abs(v.min()), abs(v.max())) if v.size else 1.0
    for i, x in enumerate(v):
        plt.text(x + (0.01 * span if x >= 0 else -0.01 * span), i, f"{x:+.2f}",
                 va="center", ha="left" if x >= 0 else "right", fontsize=8,
                 color=colors[i])
    plt.xlim(-span * 1.25, span * 1.25)
    plt.xlabel("contribuicao SHAP p/ logit de phishing")
    plt.title(titulo, fontsize=9)
    savefig(fname)


def explicar_shap_texto(mdl, tok, exemplos, max_length, phish_idx, label_names, prefixo):
    import shap
    f = make_logit_fn(mdl, tok, max_length)
    masker = shap.maskers.Text(tok)
    explainer = shap.Explainer(f, masker, output_names=label_names)
    textos = [e[0] for e in exemplos]

    log(f"  SHAP de texto ({len(textos)} exemplos, max_evals={SHAP_MAX_EVALS})...")
    sv = explainer(textos, max_evals=SHAP_MAX_EVALS, batch_size=SHAP_BATCH)

    try:
        html_str = shap.plots.text(sv[:, :, phish_idx], display=False)
        if isinstance(html_str, str):
            (OUTPUT_DIR / f"{prefixo}_shap_texto.html").write_text(html_str, encoding="utf-8")
            log(f"  salvo: {prefixo}_shap_texto.html")
    except Exception as e:
        log(f"  (html do shap pulado: {e})")

    for i, (texto, esperado) in enumerate(exemplos):
        svi = sv[i, :, phish_idx]
        barra_tokens_limpa(svi.values, svi.data,
                           f"{prefixo} | ex{i} ({esperado}) -> logit phishing\n{texto[:70]}",
                           f"{prefixo}_shap_bar_ex{i}_{esperado}.png")
    return sv


def attention_rollout(attentions):
    result = None
    for a in attentions:
        a = a[0].mean(0)
        a = a + torch.eye(a.size(0), device=a.device)
        a = a / a.sum(dim=-1, keepdim=True)
        result = a if result is None else a @ result
    return result


def explicar_atencao(mdl, tok, texto, max_length, titulo, prefixo, idx):
    enc = tok(texto, return_tensors="pt", truncation=True, max_length=max_length)
    enc = {k: v.to(device) for k, v in enc.items()}
    with torch.no_grad():
        out = mdl(**enc, output_attentions=True)
    toks = tok.convert_ids_to_tokens(enc["input_ids"][0])
    atts = out.attentions
    if atts is None:
        raise RuntimeError("attentions=None — carregue o modelo com attn_implementation='eager'")

    roll = attention_rollout(atts)
    cls_attn = roll[0].cpu().numpy()
    # remove tokens especiais ([CLS]/[SEP]/[PAD]...) que dominam o rollout e
    # esmagam os tokens informativos da URL/email
    especiais = set(tok.all_special_tokens)
    validos = [j for j in range(len(toks)) if toks[j] not in especiais]
    if not validos:
        validos = list(range(len(toks)))
    cls_v = np.array([cls_attn[j] for j in validos])
    toks_v = [_limpar_token(toks[j]) for j in validos]
    sel = np.argsort(cls_v)[::-1][:20]
    sel = sel[np.argsort(cls_v[sel])]  # exibe do menor p/ maior
    plt.figure(figsize=(7.5, max(3, len(sel) * 0.32)))
    plt.barh(range(len(sel)), cls_v[sel], color="#cc3333")
    plt.yticks(range(len(sel)), [toks_v[j] for j in sel], fontsize=9)
    plt.xlabel("Atencao do [CLS] (rollout, sem tokens especiais)")
    plt.title(f"{titulo}\n{texto[:70]}", fontsize=9)
    savefig(f"{prefixo}_atencao_tokens_ex{idx}.png")

    last = atts[-1][0].mean(0).cpu().numpy()
    n = min(len(toks), 40)
    plt.figure(figsize=(8, 7))
    plt.imshow(last[:n, :n], cmap="viridis", aspect="auto")
    plt.colorbar(fraction=0.046)
    plt.xticks(range(n), toks[:n], rotation=90, fontsize=6)
    plt.yticks(range(n), toks[:n], fontsize=6)
    plt.title(f"{titulo} — atencao ultima camada (media cabecas)", fontsize=9)
    savefig(f"{prefixo}_atencao_heatmap_ex{idx}.png")


# --------------------------------------------------------------------------
# PARTE A — DomURLs-BERT
# --------------------------------------------------------------------------
def parte_domurls():
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    log("=== PARTE A: DomURLs-BERT ===")
    tok = AutoTokenizer.from_pretrained(str(DOMURLS_DIR))
    mdl = AutoModelForSequenceClassification.from_pretrained(
        str(DOMURLS_DIR), attn_implementation="eager").to(device).eval()
    log(f"  id2label={mdl.config.id2label} vocab={mdl.config.vocab_size}")
    labels = [mdl.config.id2label[i] for i in range(mdl.config.num_labels)]
    phish = next((i for i, l in mdl.config.id2label.items() if "phish" in str(l).lower()), 1)

    explicar_shap_texto(mdl, tok, EXEMPLOS_URL, MAX_LENGTH_URL, phish, labels, "domurls")
    explicar_atencao(mdl, tok,
                     "[URL] http://paypal-verify.xyz/account [WHOIS] unknown [EXTRA] length=35 tls=0",
                     MAX_LENGTH_URL, "DomURLs-BERT (phishing)", "domurls", 0)
    explicar_atencao(mdl, tok,
                     "[URL] https://www.google.com [WHOIS] unknown [EXTRA] length=24 tls=1",
                     MAX_LENGTH_URL, "DomURLs-BERT (legitimo)", "domurls", 1)
    del mdl, tok; gc.collect()


# --------------------------------------------------------------------------
# PARTE B — DistilBERT email
# --------------------------------------------------------------------------
def parte_email():
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    log("=== PARTE B: DistilBERT email ===")
    tok = AutoTokenizer.from_pretrained(EMAIL_MODEL_ID)
    mdl = AutoModelForSequenceClassification.from_pretrained(
        EMAIL_MODEL_ID, attn_implementation="eager").to(device).eval()
    log(f"  id2label={mdl.config.id2label}")
    labels = [mdl.config.id2label[i] for i in range(mdl.config.num_labels)]
    phish = next((i for i, l in mdl.config.id2label.items() if "phish" in str(l).lower()), 1)

    explicar_shap_texto(mdl, tok, EXEMPLOS_EMAIL, MAX_LENGTH_EMAIL, phish, labels, "email")
    for i, (texto, esperado) in enumerate(EXEMPLOS_EMAIL):
        explicar_atencao(mdl, tok, texto, MAX_LENGTH_EMAIL,
                         f"DistilBERT email ({esperado})", "email", i)
    del mdl, tok; gc.collect()


# --------------------------------------------------------------------------
# PARTE C — CatBoost
# --------------------------------------------------------------------------
def parte_catboost():
    import shap
    from catboost import CatBoostClassifier, Pool
    log("=== PARTE C: CatBoost ===")
    cb = CatBoostClassifier(); cb.load_model(str(CATBOOST_CBM))
    feat = json.loads(FEATURE_COLS_JSON.read_text())
    cols, cat = feat["feature_columns"], feat["cat_features"]
    df = pd.read_csv(CATBOOST_CSV)
    X = df[cols].copy()
    for c in cat:
        X[c] = X[c].astype(str)
    y = df["label"].values

    n = min(N_EXPLAIN_CB, len(X))
    rng = np.random.RandomState(RANDOM_STATE)
    idx = rng.choice(len(X), size=n, replace=False)
    Xs = X.iloc[idx].reset_index(drop=True)
    ys = y[idx]

    log(f"  TreeSHAP em {n} amostras...")
    shap_raw = cb.get_feature_importance(Pool(Xs, cat_features=cat), type="ShapValues")
    base, vals = shap_raw[:, -1], shap_raw[:, :-1]

    X_enc = Xs.copy()
    for c in cat:
        X_enc[c] = X_enc[c].astype("category").cat.codes
    expl = shap.Explanation(values=vals, base_values=base,
                            data=X_enc.values, feature_names=cols)

    shap.plots.beeswarm(expl, max_display=24, show=False)
    plt.title("CatBoost — SHAP beeswarm (impacto por feature)", fontsize=10)
    savefig("catboost_shap_beeswarm.png")

    shap.plots.bar(expl, max_display=24, show=False)
    plt.title("CatBoost — importancia media |SHAP|", fontsize=10)
    savefig("catboost_shap_bar.png")

    for tag, cls in [("phishing", 1), ("legitimo", 0)]:
        hits = np.where(ys == cls)[0]
        if len(hits) == 0:
            continue
        i = int(hits[0])
        shap.plots.waterfall(expl[i], max_display=15, show=False)
        plt.title(f"CatBoost — waterfall ({tag}) | {df.iloc[idx[i]]['url'][:55]}", fontsize=9)
        savefig(f"catboost_shap_waterfall_{tag}.png")


def main():
    log(f"Device: {device} | saida: {OUTPUT_DIR}")
    etapas = [("DomURLs-BERT", parte_domurls),
              ("DistilBERT email", parte_email),
              ("CatBoost", parte_catboost)]
    falhas = []
    for nome, fn in etapas:
        try:
            t0 = time.time()
            fn()
            log(f"  {nome} OK ({time.time()-t0:.0f}s)")
        except Exception as e:
            import traceback
            falhas.append(nome)
            log(f"  !!! FALHA em {nome}: {e}")
            traceback.print_exc()
    log("=" * 50)
    arquivos = sorted(p.name for p in OUTPUT_DIR.glob("*"))
    log(f"Concluido. {len(arquivos)} arquivos em {OUTPUT_DIR}:")
    for a in arquivos:
        log(f"  {a}")
    if falhas:
        log(f"ATENCAO: falharam: {falhas}")
        sys.exit(1)


if __name__ == "__main__":
    main()
