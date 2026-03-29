"""
Validador do Modelo DomURLs-BERT
==================================
Envia URLs conhecidas (legitimas + phishing) para a API e gera
relatorio de acertos, erros e distribuicao de confianca.

Objetivo: diagnosticar se o modelo esta classificando corretamente
ou se ha um vies sistematico (ex: tudo como phishing).

Uso:
  pip install requests pandas tabulate
  python validar_modelo.py [--api-url http://localhost:8000] [--timeout 30]

Requisito:
  API rodando (docker-compose up ou python app.py na pasta phishing-api/)
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass

import requests

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

# ============================================================
# URLs de teste — ground truth conhecida
# ============================================================

# Legitimas: dominios bem conhecidos que NUNCA devem ser phishing
LEGITIMATE_URLS = [
    # Bancos brasileiros
    "https://www.bb.com.br/site/",
    "https://www.itau.com.br/",
    "https://banco.bradesco/html/classic/index.shtm",
    "https://www.santander.com.br/",
    "https://www.caixa.gov.br/Paginas/home-caixa.aspx",
    "https://www.nubank.com.br/",
    "https://www.banrisul.com.br/",
    # Governo BR
    "https://www.gov.br/",
    "https://www.receita.fazenda.gov.br/",
    "https://www.ibge.gov.br/",
    # Big tech global
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
    # E-commerce BR
    "https://www.mercadolivre.com.br/",
    "https://www.magazineluiza.com.br/",
    "https://www.americanas.com.br/",
    "https://www.kabum.com.br/",
    # Midia BR
    "https://www.globo.com/",
    "https://g1.globo.com/",
    "https://www.uol.com.br/",
    # Servicos
    "https://www.ifood.com.br/",
    "https://www.netflix.com/",
    "https://www.spotify.com/",
    "https://www.uber.com/",
    # AI
    "https://claude.ai/",
    "https://chatgpt.com/",
    "https://www.openai.com/",
    # Referencia
    "https://www.wikipedia.org/",
    "https://stackoverflow.com/",
]

# Phishing: URLs sinteticas com padroes tipicos de phishing
# (NAO sao URLs reais ativas — sao exemplos de formato)
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

# ============================================================
# Client features simuladas (minimas)
# ============================================================

def build_client_features(url: str) -> dict:
    """Extrai client_features de uma URL (mesma logica da extensao)."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        full = url

        vowels = sum(1 for c in hostname if c in "aeiou")
        params = full.count("&") + (1 if "?" in full else 0)

        return {
            "length": len(full),
            "dom_length": len(hostname),
            "dot": full.count("."),
            "hyphen": full.count("-"),
            "slash": full.count("/"),
            "at": full.count("@"),
            "params": params,
            "shortened": 1 if len(hostname) <= 6 and "." in hostname else 0,
            "tls": 1 if parsed.scheme == "https" else 0,
            "vowels_domain": vowels,
            "email": 1 if "@" in full and "." in full.split("@")[-1] else 0,
        }
    except Exception:
        return {
            "length": len(url), "dom_length": 0, "dot": 0, "hyphen": 0,
            "slash": 0, "at": 0, "params": 0, "shortened": 0,
            "tls": 0, "vowels_domain": 0, "email": 0,
        }


# ============================================================
# Resultado
# ============================================================

@dataclass
class PredictionResult:
    url: str
    expected: str  # "LEGITIMO" ou "PHISHING"
    predicted: str
    is_phishing: bool
    confidence: float
    analysis: str
    inference_ms: float
    correct: bool
    error: str = ""


# ============================================================
# Execucao
# ============================================================

def test_url(api_url: str, url: str, expected: str, timeout: int) -> PredictionResult:
    """Envia uma URL para a API e compara com o esperado."""
    try:
        features = build_client_features(url)
        r = requests.post(
            f"{api_url}/predict",
            json={"url": url, "client_features": features},
            timeout=timeout,
        )
        if r.status_code != 200:
            return PredictionResult(
                url=url, expected=expected, predicted="ERRO",
                is_phishing=False, confidence=0, analysis="",
                inference_ms=0, correct=False,
                error=f"HTTP {r.status_code}: {r.text[:200]}"
            )

        data = r.json()
        predicted = data["label"]
        correct = (predicted == expected)

        return PredictionResult(
            url=url,
            expected=expected,
            predicted=predicted,
            is_phishing=data["is_phishing"],
            confidence=data["confidence"],
            analysis=data.get("analysis", ""),
            inference_ms=data.get("inference_ms", 0),
            correct=correct,
        )
    except requests.exceptions.ConnectionError:
        return PredictionResult(
            url=url, expected=expected, predicted="ERRO",
            is_phishing=False, confidence=0, analysis="",
            inference_ms=0, correct=False,
            error="API offline — conexao recusada"
        )
    except Exception as e:
        return PredictionResult(
            url=url, expected=expected, predicted="ERRO",
            is_phishing=False, confidence=0, analysis="",
            inference_ms=0, correct=False, error=str(e)[:200]
        )


def print_results(results: list[PredictionResult]):
    """Imprime relatorio formatado."""

    # Separar por tipo
    legit_results = [r for r in results if r.expected == "LEGITIMO"]
    phish_results = [r for r in results if r.expected == "PHISHING"]
    errors = [r for r in results if r.error]

    if errors and all(r.error for r in results):
        print("\n" + "=" * 60)
        print("  ERRO: Todas as requisicoes falharam!")
        print(f"  {errors[0].error}")
        print("  Verifique se a API esta rodando.")
        print("=" * 60)
        return

    print("\n" + "=" * 70)
    print("  RELATORIO DE VALIDACAO DO MODELO DomURLs-BERT")
    print("=" * 70)

    # --- Metricas gerais ---
    valid = [r for r in results if not r.error]
    correct = [r for r in valid if r.correct]
    accuracy = len(correct) / len(valid) * 100 if valid else 0

    legit_correct = [r for r in legit_results if r.correct and not r.error]
    phish_correct = [r for r in phish_results if r.correct and not r.error]
    legit_valid = [r for r in legit_results if not r.error]
    phish_valid = [r for r in phish_results if not r.error]

    print(f"\n  Accuracy geral:     {accuracy:.1f}% ({len(correct)}/{len(valid)})")
    if legit_valid:
        legit_acc = len(legit_correct) / len(legit_valid) * 100
        print(f"  Accuracy legitimos: {legit_acc:.1f}% ({len(legit_correct)}/{len(legit_valid)})")
    if phish_valid:
        phish_acc = len(phish_correct) / len(phish_valid) * 100
        print(f"  Accuracy phishing:  {phish_acc:.1f}% ({len(phish_correct)}/{len(phish_valid)})")
    if errors:
        print(f"  Erros de conexao:   {len(errors)}")

    # --- Falsos positivos (legitimo classificado como phishing) ---
    fps = [r for r in legit_results if not r.correct and not r.error]
    if fps:
        print(f"\n  {'='*60}")
        print(f"  FALSOS POSITIVOS ({len(fps)}) — Legitimos classificados como PHISHING:")
        print(f"  {'='*60}")
        rows = []
        for r in fps:
            rows.append([
                r.url[:55] + "..." if len(r.url) > 55 else r.url,
                f"{r.confidence:.1f}%",
                r.predicted
            ])
        if HAS_TABULATE:
            print(tabulate(rows, headers=["URL", "Confianca", "Predicao"], tablefmt="simple"))
        else:
            for row in rows:
                print(f"    {row[0]:58s} {row[1]:>8s}  {row[2]}")

    # --- Falsos negativos (phishing classificado como legitimo) ---
    fns = [r for r in phish_results if not r.correct and not r.error]
    if fns:
        print(f"\n  {'='*60}")
        print(f"  FALSOS NEGATIVOS ({len(fns)}) — Phishing classificados como LEGITIMO:")
        print(f"  {'='*60}")
        rows = []
        for r in fns:
            rows.append([
                r.url[:55] + "..." if len(r.url) > 55 else r.url,
                f"{r.confidence:.1f}%",
                r.predicted
            ])
        if HAS_TABULATE:
            print(tabulate(rows, headers=["URL", "Confianca", "Predicao"], tablefmt="simple"))
        else:
            for row in rows:
                print(f"    {row[0]:58s} {row[1]:>8s}  {row[2]}")

    # --- Distribuicao de confianca ---
    print(f"\n  {'='*60}")
    print("  DISTRIBUICAO DE CONFIANCA:")
    print(f"  {'='*60}")

    for label, group in [("LEGITIMOS", legit_valid), ("PHISHING", phish_valid)]:
        if not group:
            continue
        confs = [r.confidence for r in group]
        avg = sum(confs) / len(confs)
        mn = min(confs)
        mx = max(confs)
        print(f"\n  {label} (n={len(group)}):")
        print(f"    Media:  {avg:.1f}%")
        print(f"    Min:    {mn:.1f}%")
        print(f"    Max:    {mx:.1f}%")

        # Histograma simples
        bins = {"<50%": 0, "50-70%": 0, "70-90%": 0, "90-100%": 0}
        for c in confs:
            if c < 50: bins["<50%"] += 1
            elif c < 70: bins["50-70%"] += 1
            elif c < 90: bins["70-90%"] += 1
            else: bins["90-100%"] += 1
        for b, cnt in bins.items():
            bar = "#" * cnt
            print(f"    {b:>8s}: {cnt:3d} {bar}")

    # --- Detalhes completos ---
    print(f"\n  {'='*60}")
    print("  DETALHES COMPLETOS:")
    print(f"  {'='*60}")

    for label, group in [("LEGITIMOS", legit_results), ("PHISHING", phish_results)]:
        print(f"\n  --- {label} ---")
        for r in group:
            status = "OK" if r.correct else ("ERRO" if r.error else "FALHA")
            icon = "+" if r.correct else ("-" if r.error else "X")
            conf_str = f"{r.confidence:.1f}%" if not r.error else "N/A"
            pred = r.predicted if not r.error else r.error[:30]
            url_short = r.url[:50] + "..." if len(r.url) > 50 else r.url
            print(f"  [{icon}] {url_short:55s} -> {pred:10s} ({conf_str:>7s}) {status}")

    # --- Diagnostico ---
    print(f"\n  {'='*60}")
    print("  DIAGNOSTICO:")
    print(f"  {'='*60}")

    if accuracy >= 90:
        print("  Modelo parece funcionar corretamente.")
    elif accuracy >= 70:
        print("  Modelo tem desempenho razoavel mas com erros significativos.")
    else:
        print("  ATENCAO: Modelo com desempenho ruim!")

    if fps and len(fps) > len(legit_valid) * 0.3:
        print("  PROBLEMA: Alta taxa de falsos positivos!")
        print("  O modelo esta classificando muitos sites legitimos como phishing.")
        print("  Possivel causa: modelo nao foi treinado com features nesse formato,")
        print("  ou as classes estao invertidas (label 0 vs 1).")

    if fns and len(fns) > len(phish_valid) * 0.3:
        print("  PROBLEMA: Alta taxa de falsos negativos!")
        print("  O modelo esta deixando passar muitos sites de phishing.")

    # Checa se tudo esta sendo classificado igual
    all_predictions = [r.predicted for r in valid]
    unique_preds = set(all_predictions)
    if len(unique_preds) == 1:
        print(f"\n  CRITICO: Todas as {len(valid)} URLs foram classificadas como {unique_preds.pop()}!")
        print("  O modelo parece estar com bias extremo ou quebrado.")
        print("  Verifique:")
        print("    1. Se o modelo foi carregado corretamente")
        print("    2. Se as labels (classe 0 vs 1) estao corretas")
        print("    3. Se o formato de feature_text corresponde ao treinamento")

    # --- Salvar JSON ---
    output = {
        "accuracy": accuracy,
        "total": len(valid),
        "correct": len(correct),
        "false_positives": len(fps),
        "false_negatives": len(fns),
        "errors": len(errors),
        "results": [
            {
                "url": r.url,
                "expected": r.expected,
                "predicted": r.predicted,
                "confidence": r.confidence,
                "correct": r.correct,
                "inference_ms": r.inference_ms,
                "error": r.error,
            }
            for r in results
        ]
    }
    with open("validacao_modelo.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\n  Resultados salvos em: validacao_modelo.json")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="Validar modelo DomURLs-BERT via API")
    parser.add_argument("--api-url", default="http://localhost:8000",
                        help="URL base da API (default: http://localhost:8000)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Timeout por request em segundos (default: 30)")
    args = parser.parse_args()

    print("=" * 70)
    print("  VALIDACAO DO MODELO DomURLs-BERT")
    print(f"  API: {args.api_url}")
    print("=" * 70)

    # Verificar se API esta online
    print("\n  Verificando API...")
    try:
        r = requests.get(f"{args.api_url}/health", timeout=5)
        if r.status_code == 200:
            data = r.json()
            print(f"  API online — modelo: {data.get('model_loaded')}, device: {data.get('device')}")
        else:
            print(f"  API respondeu com HTTP {r.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"  API offline em {args.api_url}")
        print("  Inicie a API antes de rodar este script:")
        print("    cd phishing-api && docker-compose up")
        print("    ou: cd phishing-api && python app.py")
        sys.exit(1)

    # Rodar testes
    results = []
    total = len(LEGITIMATE_URLS) + len(PHISHING_URLS)

    print(f"\n  Testando {len(LEGITIMATE_URLS)} URLs legitimas...")
    for i, url in enumerate(LEGITIMATE_URLS, 1):
        print(f"    [{i}/{total}] {url[:60]}...", end="", flush=True)
        result = test_url(args.api_url, url, "LEGITIMO", args.timeout)
        icon = "OK" if result.correct else ("ERR" if result.error else "FAIL")
        print(f" -> {result.predicted} ({result.confidence:.1f}%) [{icon}]")
        results.append(result)

    print(f"\n  Testando {len(PHISHING_URLS)} URLs de phishing...")
    for i, url in enumerate(PHISHING_URLS, len(LEGITIMATE_URLS) + 1):
        print(f"    [{i}/{total}] {url[:60]}...", end="", flush=True)
        result = test_url(args.api_url, url, "PHISHING", args.timeout)
        icon = "OK" if result.correct else ("ERR" if result.error else "FAIL")
        print(f" -> {result.predicted} ({result.confidence:.1f}%) [{icon}]")
        results.append(result)

    print_results(results)


if __name__ == "__main__":
    main()
