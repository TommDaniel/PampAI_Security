"""
Validacao completa da arquitetura em cascata: BERT vs CatBoost vs Cascade.

Testa ~100 URLs (50 legitimas + 50 phishing) em 3 modos:
  1. BERT sozinho
  2. CatBoost sozinho
  3. Cascata (BERT + CatBoost)

Gera metricas comparativas: accuracy, precision, recall, F1, FP, FN.
"""

import argparse
import json
import re
import sys
import time
from urllib.parse import urlparse

import requests

# ============================================================
# Ground truth: 50 URLs legitimas + 50 URLs phishing
# ============================================================

LEGITIMATE_URLS = [
    # Bancos brasileiros
    "https://www.bb.com.br",
    "https://www.itau.com.br",
    "https://www.bradesco.com.br",
    "https://www.santander.com.br",
    "https://www.caixa.gov.br",
    "https://nubank.com.br",
    "https://www.sicoob.com.br",
    "https://www.banrisul.com.br",
    "https://www.sicredi.com.br",
    "https://banco.bradesco",
    # Governo brasileiro
    "https://www.gov.br",
    "https://www.receita.fazenda.gov.br",
    "https://www.tse.jus.br",
    "https://www.stf.jus.br",
    "https://www.camara.leg.br",
    # Tech giants
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.facebook.com",
    "https://www.instagram.com",
    "https://www.twitter.com",
    "https://www.linkedin.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.amazon.com",
    "https://github.com",
    "https://www.netflix.com",
    "https://www.spotify.com",
    "https://www.whatsapp.com",
    "https://www.wikipedia.org",
    "https://www.reddit.com",
    # E-commerce Brasil
    "https://www.mercadolivre.com.br",
    "https://www.americanas.com.br",
    "https://www.magazineluiza.com.br",
    "https://www.casasbahia.com.br",
    "https://www.submarino.com.br",
    # Servicos
    "https://www.uol.com.br",
    "https://www.globo.com",
    "https://www.terra.com.br",
    "https://outlook.live.com",
    "https://mail.google.com",
    # Universidades
    "https://www.usp.br",
    "https://www.unicamp.br",
    "https://www.ufrgs.br",
    "https://www.ufsc.br",
    "https://www.pucrs.br",
    # AI/Tech
    "https://claude.ai",
    "https://chatgpt.com",
    "https://openai.com",
    "https://stackoverflow.com",
    "https://www.cloudflare.com",
    "https://www.docker.com",
]

PHISHING_URLS = [
    # IP-based
    "http://192.168.1.100/login/bancodobrasil",
    "http://45.33.32.156/secure/itau-login.php",
    "http://185.234.219.45/caixa/atualizar-dados",
    "http://103.45.67.89/netflix/verify-account",
    "http://91.134.200.33/paypal-confirm/index.html",
    # Typosquatting / homoglifos
    "http://www.g00gle-login.com/accounts/verify",
    "http://www.faceb00k-security.com/login",
    "http://www.amaz0n-verify.com/account/confirm",
    "http://www.paypa1-secure.com/update-info",
    "http://www.netfl1x-account.com/billing/update",
    # Subdominios suspeitos
    "http://login.bradesco.com.secure-update.xyz/verify",
    "http://itau.com.br.account-verify.tk/login",
    "http://bb.com.br.secure-banking.ml/atualizar",
    "http://santander.com.br.verify-account.ga/login",
    "http://nubank.com.br.update-security.cf/dados",
    # Dominios longos/suspeitos
    "http://secure-banking-update-your-account-now-bradesco.com/login",
    "http://verificacao-conta-bancaria-urgente-caixa.com.br.xyz.com/form",
    "http://atualizacao-cadastro-obrigatoria-bb.net/verify",
    "http://confirmar-identidade-itau-seguranca.org/dados",
    "http://revalidar-token-seguranca-nubank-app.com/auth",
    # Phishing com marcas conhecidas
    "http://microsoft-365-security-alert.com/verify",
    "http://apple-id-suspended-verify.com/login",
    "http://google-account-recovery-alert.com/signin",
    "http://instagram-verify-badge.com/confirm",
    "http://linkedin-profile-security.com/update",
    # URLs com caracteres suspeitos
    "http://www.banco-do-brasil-seguro.com/login?ref=email&id=12345",
    "http://caixa-gov-br.com/atualizar-cadastro?token=abc123",
    "http://receita-federal-restituicao.com/consultar?cpf=",
    "http://correios-rastreamento-encomenda.com/tracking?code=BR123",
    "http://detran-consulta-multas.net/verificar?placa=ABC1234",
    # Encurtadores / redirecionamento
    "http://bit.ly/3xPhish123",
    "http://tinyurl.com/fake-banco-login",
    # Phishing em ingles
    "http://account-verify-amazon-security.com/signin",
    "http://chase-bank-secure-login-verify.com/auth",
    "http://wells-fargo-account-alert.com/verify",
    "http://bank-of-america-security-update.com/login",
    "http://citibank-verify-account-update.com/secure",
    # Phishing com HTTPS falso
    "https://secure-login-bradesco.tk/app/verify",
    "https://www.itau-seguranca-digital.xyz/login",
    "https://caixa-atualizacao-obrigatoria.ml/form",
    "https://santander-verificacao-conta.ga/dados",
    "https://nubank-confirmar-identidade.cf/auth",
    # Dominios .zip / .top / .xyz suspeitos
    "http://login-bancodobrasil.top/verify",
    "http://itau-internet-banking.xyz/secure",
    "http://caixa-economica-federal.top/atualizar",
    "http://bradesco-prime.xyz/conta/verificar",
    "http://banco-inter-app.top/login/seguro",
    # Mais phishing com padroes variados
    "http://suporte-mercadolivre.com/verificar-conta",
    "http://alert-netflix-payment.com/update-billing",
    "http://spotify-premium-free.com/claim",
]


def extract_client_features(url: str) -> dict:
    """Extrai as 11 client features de uma URL (replica do TypeScript)."""
    url_str = url if url.startswith("http") else f"http://{url}"
    try:
        parsed = urlparse(url_str)
    except Exception:
        parsed = urlparse("http://invalid")

    hostname = (parsed.hostname or "").lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]

    parts = hostname.split(".")
    domain = parts[-2] if len(parts) >= 2 else hostname

    shorteners = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "is.gd", "cli.re", "go2l.ink", "x.co", "shorte.st",
        "tr.im", "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc"
    ]

    return {
        "length": len(url),
        "dom_length": len(domain),
        "dot": url.count("."),
        "hyphen": url.count("-"),
        "slash": url.count("/"),
        "at": url.count("@"),
        "params": url.count("=") if "?" in url else 0,
        "shortened": 1 if any(hostname == s or hostname.endswith("." + s) for s in shorteners) else 0,
        "tls": 1 if url.startswith("https") else 0,
        "vowels_domain": sum(1 for c in domain if c in "aeiouAEIOU"),
        "email": 1 if re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", url) else 0,
    }


def call_api(api_url: str, url: str, mode: str, timeout: int) -> dict:
    """Chama a API com um modo especifico."""
    features = extract_client_features(url)
    payload = {
        "url": url,
        "client_features": features,
        "mode": mode,
    }
    try:
        resp = requests.post(
            f"{api_url}/predict",
            json=payload,
            timeout=timeout,
        )
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"HTTP {resp.status_code}", "url": url}
    except requests.exceptions.Timeout:
        return {"error": "timeout", "url": url}
    except Exception as e:
        return {"error": str(e), "url": url}


def compute_metrics(results: list) -> dict:
    """Calcula metricas a partir dos resultados."""
    tp = fp = tn = fn = 0
    errors = 0
    latencies = []

    for r in results:
        if "error" in r:
            errors += 1
            continue

        predicted = r["predicted_phishing"]
        actual = r["actual_phishing"]
        latencies.append(r.get("inference_ms", 0))

        if actual and predicted:
            tp += 1
        elif actual and not predicted:
            fn += 1
        elif not actual and predicted:
            fp += 1
        else:
            tn += 1

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total * 100 if total > 0 else 0
    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "total": total,
        "errors": errors,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": round(accuracy, 1),
        "precision": round(precision, 1),
        "recall": round(recall, 1),
        "f1": round(f1, 1),
        "latency_mean_ms": round(sum(latencies) / len(latencies), 1) if latencies else 0,
        "latency_p50_ms": round(sorted(latencies)[len(latencies) // 2], 1) if latencies else 0,
        "latency_p95_ms": round(sorted(latencies)[int(len(latencies) * 0.95)], 1) if latencies else 0,
    }


def run_validation(api_url: str, mode: str, timeout: int) -> tuple:
    """Roda validacao em um modo especifico. Retorna (metrics, results, fps, fns)."""
    results = []
    fps = []
    fns = []

    all_urls = [(url, False) for url in LEGITIMATE_URLS] + [(url, True) for url in PHISHING_URLS]

    for i, (url, is_phishing) in enumerate(all_urls):
        resp = call_api(api_url, url, mode, timeout)

        if "error" in resp:
            results.append({"url": url, "error": resp["error"]})
            continue

        predicted = resp.get("is_phishing", False)
        confidence = resp.get("confidence", 0)
        source = resp.get("source", "?")

        result = {
            "url": url,
            "actual_phishing": is_phishing,
            "predicted_phishing": predicted,
            "confidence": confidence,
            "source": source,
            "inference_ms": resp.get("inference_ms", 0),
            "correct": predicted == is_phishing,
        }
        results.append(result)

        if not is_phishing and predicted:
            fps.append(f"  FP: {url} ({confidence:.1f}%) [{source}]")
        elif is_phishing and not predicted:
            fns.append(f"  FN: {url} ({confidence:.1f}%) [{source}]")

        # Progress
        done = i + 1
        total = len(all_urls)
        print(f"\r  [{mode}] {done}/{total}", end="", flush=True)

    print()
    metrics = compute_metrics(results)
    return metrics, results, fps, fns


def print_header(title: str):
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_metrics(mode: str, metrics: dict, fps: list, fns: list):
    print(f"\n--- {mode.upper()} ---")
    print(f"  Accuracy:  {metrics['accuracy']}%  ({metrics['tp']+metrics['tn']}/{metrics['total']})")
    print(f"  Precision: {metrics['precision']}%")
    print(f"  Recall:    {metrics['recall']}%")
    print(f"  F1-Score:  {metrics['f1']}%")
    print(f"  TP: {metrics['tp']}  FP: {metrics['fp']}  TN: {metrics['tn']}  FN: {metrics['fn']}  Errors: {metrics['errors']}")
    print(f"  Latencia media: {metrics['latency_mean_ms']}ms  P50: {metrics['latency_p50_ms']}ms  P95: {metrics['latency_p95_ms']}ms")

    if fps:
        print(f"\n  Falsos Positivos ({len(fps)}):")
        for fp in fps:
            print(fp)
    if fns:
        print(f"\n  Falsos Negativos ({len(fns)}):")
        for fn in fns:
            print(fn)


def main():
    parser = argparse.ArgumentParser(description="Validacao da arquitetura em cascata")
    parser.add_argument("--api-url", default="http://localhost:8000", help="URL base da API")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout por request (s)")
    parser.add_argument("--output", default="validacao_cascata.json", help="Arquivo de saida JSON")
    args = parser.parse_args()

    # Health check
    print(f"API: {args.api_url}")
    try:
        health = requests.get(f"{args.api_url}/health", timeout=5).json()
        print(f"Status: {health.get('status')} | Cascade: {health.get('cascade_enabled')} | Device: {health.get('device')}")
    except Exception as e:
        print(f"ERRO: API inacessivel - {e}")
        sys.exit(1)

    total_urls = len(LEGITIMATE_URLS) + len(PHISHING_URLS)
    print(f"\nURLs: {len(LEGITIMATE_URLS)} legitimas + {len(PHISHING_URLS)} phishing = {total_urls}")

    modes = ["bert", "catboost", "cascade"]
    all_results = {}

    print_header("VALIDACAO DA ARQUITETURA EM CASCATA")

    for mode in modes:
        print(f"\nTestando modo: {mode}...")
        start = time.time()
        metrics, results, fps, fns = run_validation(args.api_url, mode, args.timeout)
        elapsed = time.time() - start
        print_metrics(mode, metrics, fps, fns)
        print(f"  Tempo total: {elapsed:.1f}s")

        all_results[mode] = {
            "metrics": metrics,
            "false_positives": fps,
            "false_negatives": fns,
            "details": results,
        }

    # Tabela comparativa
    print_header("COMPARACAO FINAL")
    print(f"\n{'Metrica':<15} {'BERT':>10} {'CatBoost':>10} {'Cascata':>10}")
    print("-" * 47)
    for key in ["accuracy", "precision", "recall", "f1"]:
        b = all_results["bert"]["metrics"][key]
        c = all_results["catboost"]["metrics"][key]
        ca = all_results["cascade"]["metrics"][key]
        unit = "%"
        print(f"{key.capitalize():<15} {b:>9.1f}{unit} {c:>9.1f}{unit} {ca:>9.1f}{unit}")

    for key, label in [("fp", "Falsos Pos."), ("fn", "Falsos Neg.")]:
        b = all_results["bert"]["metrics"][key]
        c = all_results["catboost"]["metrics"][key]
        ca = all_results["cascade"]["metrics"][key]
        print(f"{label:<15} {b:>10} {c:>10} {ca:>10}")

    for key, label in [("latency_mean_ms", "Latencia med."), ("latency_p50_ms", "Latencia P50")]:
        b = all_results["bert"]["metrics"][key]
        c = all_results["catboost"]["metrics"][key]
        ca = all_results["cascade"]["metrics"][key]
        print(f"{label:<15} {b:>8.1f}ms {c:>8.1f}ms {ca:>8.1f}ms")

    # Salvar JSON
    output = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "api_url": args.api_url,
        "total_urls": total_urls,
        "legitimate_count": len(LEGITIMATE_URLS),
        "phishing_count": len(PHISHING_URLS),
        "results": {
            mode: {
                "metrics": all_results[mode]["metrics"],
                "false_positives": [fp.strip() for fp in all_results[mode]["false_positives"]],
                "false_negatives": [fn.strip() for fn in all_results[mode]["false_negatives"]],
            }
            for mode in modes
        },
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    print(f"\nResultados salvos em {args.output}")


if __name__ == "__main__":
    main()
