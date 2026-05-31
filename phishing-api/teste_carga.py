#!/usr/bin/env python3
"""
Q8 da banca — teste de carga da API sob concorrencia.

Mede vazao (req/s) e latencia (P50/P95/P99) do endpoint /predict variando o
numero de requisicoes SIMULTANEAS. Responde "quantas requisicoes a API aguenta
antes do P95 dobrar" e "qual a latencia sob concorrencia".

Diferente de test_performance.py (que usa modelo MOCKADO e chamadas sequenciais),
este script bate na API REAL ja em execucao, com inferencia de verdade.

Pre-requisitos (rodar na maquina do autor, NAO precisa de GPU — inferencia em CPU):
    cd phishing-api && docker compose up -d        # sobe a API com o modelo real
    python teste_carga.py --url http://localhost:8000

Uso:
    python teste_carga.py [--url URL] [--niveis 1,2,4,8,16,32] [--por-nivel 200]
"""
import argparse
import json
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

URLS_TESTE = [
    "https://www.google.com", "http://paypal-verify.xyz/account",
    "https://www.bb.com.br", "http://192.168.1.1.login.xyz/steal",
    "https://www.mercadolivre.com.br", "http://bb-seguranca.ml/acesso",
]


def uma_requisicao(api_url, payload):
    req = urllib.request.Request(
        api_url.rstrip("/") + "/predict",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()
        ok = True
    except Exception:
        ok = False
    return (time.perf_counter() - t0) * 1000.0, ok  # ms


def percentil(vals, p):
    if not vals:
        return 0.0
    s = sorted(vals)
    return s[min(len(s) - 1, int(len(s) * p))]


def rodar_nivel(api_url, concorrencia, total):
    cargas = [{"url": URLS_TESTE[i % len(URLS_TESTE)]} for i in range(total)]
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concorrencia) as ex:
        res = list(ex.map(lambda c: uma_requisicao(api_url, c), cargas))
    dur = time.perf_counter() - t0
    lat = [ms for ms, ok in res if ok]
    erros = sum(1 for _, ok in res if not ok)
    return {
        "concorrencia": concorrencia,
        "req_total": total,
        "erros": erros,
        "vazao_req_s": round(total / dur, 1),
        "p50_ms": round(percentil(lat, 0.50), 1),
        "p95_ms": round(percentil(lat, 0.95), 1),
        "p99_ms": round(percentil(lat, 0.99), 1),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--niveis", default="1,2,4,8,16,32")
    ap.add_argument("--por-nivel", type=int, default=200)
    args = ap.parse_args()

    niveis = [int(x) for x in args.niveis.split(",")]
    print(f"API: {args.url} | {args.por_nivel} req por nivel | niveis={niveis}\n")
    print(f"{'conc':>5} {'vazao/s':>9} {'P50':>7} {'P95':>7} {'P99':>7} {'erros':>6}")
    base_p95 = None
    for c in niveis:
        r = rodar_nivel(args.url, c, args.por_nivel)
        if base_p95 is None:
            base_p95 = r["p95_ms"]
        dobrou = " <-- P95 dobrou" if base_p95 and r["p95_ms"] >= 2 * base_p95 else ""
        print(f"{r['concorrencia']:5d} {r['vazao_req_s']:9.1f} {r['p50_ms']:7.1f} "
              f"{r['p95_ms']:7.1f} {r['p99_ms']:7.1f} {r['erros']:6d}{dobrou}")


if __name__ == "__main__":
    main()
