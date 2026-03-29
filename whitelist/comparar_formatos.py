"""
Comparacao: URL bruta vs formato multimodal no DomURLs-BERT fine-tuned.

Carrega o modelo localmente e testa as mesmas URLs em dois formatos:
  1. URL bruta (apenas a URL como texto)
  2. Formato multimodal ([URL] url [WHOIS] unknown [EXTRA] feat=val ...)

Mostra accuracy e FP/FN de cada formato para decidir qual usar em producao.

Uso:
  cd phishing-api
  python ../whitelist/comparar_formatos.py [--model-path model]
"""

import argparse
import os
import sys
from urllib.parse import urlparse

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer


# ============================================================
# URLs de teste (mesmas do validar_modelo.py)
# ============================================================

LEGITIMATE_URLS = [
    "https://www.bb.com.br/site/",
    "https://www.itau.com.br/",
    "https://banco.bradesco/html/classic/index.shtm",
    "https://www.santander.com.br/",
    "https://www.caixa.gov.br/Paginas/home-caixa.aspx",
    "https://www.nubank.com.br/",
    "https://www.banrisul.com.br/",
    "https://www.gov.br/",
    "https://www.receita.fazenda.gov.br/",
    "https://www.ibge.gov.br/",
    "https://www.google.com/",
    "https://www.google.com.br/",
    "https://www.youtube.com/",
    "https://www.facebook.com/",
    "https://www.instagram.com/",
    "https://www.linkedin.com/",
    "https://github.com/",
    "https://www.microsoft.com/",
    "https://www.apple.com/",
    "https://www.amazon.com/",
    "https://www.amazon.com.br/",
    "https://www.mercadolivre.com.br/",
    "https://www.magazineluiza.com.br/",
    "https://www.americanas.com.br/",
    "https://www.kabum.com.br/",
    "https://www.globo.com/",
    "https://g1.globo.com/",
    "https://www.uol.com.br/",
    "https://www.ifood.com.br/",
    "https://www.netflix.com/",
    "https://www.spotify.com/",
    "https://www.uber.com/",
    "https://claude.ai/",
    "https://chatgpt.com/",
    "https://www.openai.com/",
    "https://www.wikipedia.org/",
    "https://stackoverflow.com/",
]

PHISHING_URLS = [
    "http://192.168.1.1.login-verify-account.com/signin",
    "http://secure-paypal-login.com.phish.example.net/verify",
    "http://www.goggle-accounts.com/ServiceLogin",
    "http://bradesc0-seguranca.com/internet/login",
    "http://bb-atualizacao-seguranca.tk/acesso",
    "http://caixa-gov-br.desbloqueio.xyz/login",
    "http://itau-token-seguro.ml/validar",
    "http://login.microsoft.com.secure-verify.xyz/oauth",
    "http://apple-id-verify.com/locked/confirm",
    "http://netflix-payment-update.com/billing",
    "http://amazon-order-confirm.xyz/track",
    "http://facebook-security-alert.com/checkpoint",
    "http://update-whatsapp.com/verify",
    "http://instagram-verify-badge.com/confirm",
    "http://linkedin-security.com/verify",
    "http://google-drive-share.xyz/document",
    "http://dropbox-file-share.tk/download",
    "http://nubank-desbloqueio.com/app",
    "http://mercadolivre-compra.xyz/checkout",
    "http://correios-rastreio.tk/encomenda",
    "http://receita-federal-restituicao.com/consulta",
    "http://detran-multa.xyz/consultar",
    "http://gov-br-atualizar.com/meugovbr",
    "http://192.168.0.1/admin/phishing-kit/index.html",
    "http://xn--fcebook-9db.com/login",
]


THRESHOLD = 0.65


def build_client_features(url: str) -> dict:
    """Extrai client features de uma URL."""
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        hostname = parsed.hostname or ""
        vowels = sum(1 for c in hostname if c in "aeiou")
        params = url.count("&") + (1 if "?" in url else 0)
        return {
            "length": len(url),
            "dom_length": len(hostname),
            "dot": url.count("."),
            "hyphen": url.count("-"),
            "slash": url.count("/"),
            "at": url.count("@"),
            "params": params,
            "shortened": 1 if len(hostname) <= 6 and "." in hostname else 0,
            "tls": 1 if parsed.scheme == "https" else 0,
            "vowels_domain": vowels,
            "email": 1 if "@" in url and "." in url.split("@")[-1] else 0,
        }
    except Exception:
        return {
            "length": len(url), "dom_length": 0, "dot": 0, "hyphen": 0,
            "slash": 0, "at": 0, "params": 0, "shortened": 0,
            "tls": 0, "vowels_domain": 0, "email": 0,
        }


def build_multimodal_text(url: str) -> str:
    """Formato multimodal: [URL] url [WHOIS] unknown [EXTRA] feat=val ..."""
    cf = build_client_features(url)
    ordered = [
        ("length", cf["length"]),
        ("dom_length", cf["dom_length"]),
        ("dot", cf["dot"]),
        ("hyphen", cf["hyphen"]),
        ("slash", cf["slash"]),
        ("at", cf["at"]),
        ("params", cf["params"]),
        ("shortened", cf["shortened"]),
        ("tls", cf["tls"]),
        ("vowels_domain", cf["vowels_domain"]),
        ("email", cf["email"]),
    ]
    extra = " ".join(f"{k}={v}" for k, v in ordered)
    return f"[URL] {url} [WHOIS] unknown [EXTRA] {extra}"


def predict(model, tokenizer, text: str, max_len: int, device) -> tuple:
    """Retorna (is_phishing, confidence, phishing_prob)."""
    inputs = tokenizer(text, return_tensors="pt", truncation=True,
                       max_length=max_len, padding=True)
    inputs = {k: v.to(device) for k, v in inputs.items()}
    with torch.no_grad():
        probs = torch.softmax(model(**inputs).logits[0], dim=-1)
    p_phish = probs[1].item()
    is_phishing = p_phish > THRESHOLD
    confidence = (p_phish if is_phishing else 1.0 - p_phish) * 100
    return is_phishing, confidence, p_phish


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-path", default="model")
    args = parser.parse_args()

    if not os.path.isdir(args.model_path):
        print(f"Modelo nao encontrado: {args.model_path}")
        print("Execute a partir da pasta phishing-api/")
        sys.exit(1)

    print("Carregando modelo...")
    tokenizer = AutoTokenizer.from_pretrained(args.model_path)
    model = AutoModelForSequenceClassification.from_pretrained(args.model_path)
    device = torch.device("cpu")
    model.to(device)
    model.eval()

    # Detectar modo multimodal
    unk_id = tokenizer.convert_tokens_to_ids("[UNK]")
    url_id = tokenizer.convert_tokens_to_ids("[URL]")
    has_special = url_id != unk_id
    print(f"Tokens especiais: {'SIM' if has_special else 'NAO'}")
    print(f"Threshold: {THRESHOLD}")

    all_urls = [(u, "LEGITIMO") for u in LEGITIMATE_URLS] + \
               [(u, "PHISHING") for u in PHISHING_URLS]

    # ============================================================
    # Testar ambos os formatos
    # ============================================================
    results_raw = []
    results_multi = []

    print(f"\nTestando {len(all_urls)} URLs em 2 formatos...\n")

    for url, expected in all_urls:
        # Formato 1: URL bruta
        is_ph_raw, conf_raw, prob_raw = predict(model, tokenizer, url, 128, device)
        pred_raw = "PHISHING" if is_ph_raw else "LEGITIMO"
        results_raw.append((url, expected, pred_raw, conf_raw, prob_raw))

        # Formato 2: Multimodal
        multi_text = build_multimodal_text(url)
        is_ph_multi, conf_multi, prob_multi = predict(model, tokenizer, multi_text, 192, device)
        pred_multi = "PHISHING" if is_ph_multi else "LEGITIMO"
        results_multi.append((url, expected, pred_multi, conf_multi, prob_multi))

    # ============================================================
    # Relatorio
    # ============================================================
    def report(name, results):
        correct = sum(1 for _, exp, pred, _, _ in results if exp == pred)
        total = len(results)
        acc = correct / total * 100

        legit = [(u, e, p, c, pr) for u, e, p, c, pr in results if e == "LEGITIMO"]
        phish = [(u, e, p, c, pr) for u, e, p, c, pr in results if e == "PHISHING"]

        legit_ok = sum(1 for _, e, p, _, _ in legit if e == p)
        phish_ok = sum(1 for _, e, p, _, _ in phish if e == p)

        fps = [(u, c, pr) for u, e, p, c, pr in legit if e != p]
        fns = [(u, c, pr) for u, e, p, c, pr in phish if e != p]

        print(f"\n{'='*70}")
        print(f"  {name}")
        print(f"{'='*70}")
        print(f"  Accuracy geral:     {acc:.1f}% ({correct}/{total})")
        print(f"  Accuracy legitimos: {legit_ok}/{len(legit)} ({legit_ok/len(legit)*100:.1f}%)")
        print(f"  Accuracy phishing:  {phish_ok}/{len(phish)} ({phish_ok/len(phish)*100:.1f}%)")
        print(f"  Falsos positivos:   {len(fps)}")
        print(f"  Falsos negativos:   {len(fns)}")

        if fps:
            print(f"\n  Falsos Positivos (legitimos marcados como PHISHING):")
            for u, c, pr in fps:
                print(f"    {u[:58]:60s} P(phish)={pr:.1%}  conf={c:.1f}%")

        if fns:
            print(f"\n  Falsos Negativos (phishing marcados como LEGITIMO):")
            for u, c, pr in fns:
                print(f"    {u[:58]:60s} P(phish)={pr:.1%}  conf={c:.1f}%")

        return acc, len(fps), len(fns)

    acc_raw, fp_raw, fn_raw = report("FORMATO 1: URL BRUTA (max_length=128)", results_raw)
    acc_multi, fp_multi, fn_multi = report("FORMATO 2: MULTIMODAL [URL]...[WHOIS]...[EXTRA]... (max_length=192)", results_multi)

    # ============================================================
    # Comparacao final
    # ============================================================
    print(f"\n{'='*70}")
    print("  COMPARACAO FINAL")
    print(f"{'='*70}")
    print(f"  {'Metrica':<25s} {'URL Bruta':>12s} {'Multimodal':>12s}")
    print(f"  {'-'*25} {'-'*12} {'-'*12}")
    print(f"  {'Accuracy':<25s} {acc_raw:>11.1f}% {acc_multi:>11.1f}%")
    print(f"  {'Falsos Positivos':<25s} {fp_raw:>12d} {fp_multi:>12d}")
    print(f"  {'Falsos Negativos':<25s} {fn_raw:>12d} {fn_multi:>12d}")

    if acc_raw > acc_multi:
        diff = acc_raw - acc_multi
        print(f"\n  >> URL BRUTA e melhor por {diff:.1f}pp")
        print(f"  >> Recomendacao: desativar modo multimodal na API")
    elif acc_multi > acc_raw:
        diff = acc_multi - acc_raw
        print(f"\n  >> MULTIMODAL e melhor por {diff:.1f}pp")
        print(f"  >> Recomendacao: manter modo multimodal na API")
    else:
        print(f"\n  >> Empate. URL bruta e mais simples e rapida.")

    # Lado a lado detalhado
    print(f"\n{'='*70}")
    print("  DETALHES LADO A LADO")
    print(f"{'='*70}")
    print(f"  {'URL':<45s} | {'Esp':>5s} | {'Raw':>5s} {'P%':>5s} | {'Multi':>5s} {'P%':>5s}")
    print(f"  {'-'*45}-+-{'-'*5}-+-{'-'*5}-{'-'*5}-+-{'-'*5}-{'-'*5}")

    for i in range(len(all_urls)):
        url, expected = all_urls[i]
        _, _, pred_r, _, prob_r = results_raw[i]
        _, _, pred_m, _, prob_m = results_multi[i]

        exp_short = "LEG" if expected == "LEGITIMO" else "PHI"
        raw_short = "LEG" if pred_r == "LEGITIMO" else "PHI"
        mul_short = "LEG" if pred_m == "LEGITIMO" else "PHI"

        raw_mark = " " if pred_r == expected else "X"
        mul_mark = " " if pred_m == expected else "X"

        url_short = url[:45]
        print(f"  {url_short:<45s} | {exp_short:>5s} | {raw_short:>4s}{raw_mark} {prob_r:>4.0%} | {mul_short:>4s}{mul_mark} {prob_m:>4.0%}")

    print("=" * 70)


if __name__ == "__main__":
    main()
