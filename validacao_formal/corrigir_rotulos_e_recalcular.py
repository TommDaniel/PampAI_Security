"""
corrigir_rotulos_e_recalcular.py
================================

Re-rotula URLs ``*.gov.br`` / ``*.leg.br`` / ``*.jus.br`` que foram
inseridas na ``blacklist.json`` upstream por engano (são órgãos públicos
brasileiros legítimos — câmaras municipais, conselhos profissionais,
prefeituras, sistemas de licitação) e recalcula as métricas a partir do
``validacao_formal.json`` produzido pela rodada original.

A reclassificação é manual e justificada: a regra é que se o domínio
termina exatamente em ``.gov.br|leg.br|jus.br`` (sem sufixo `.com`/`.tk`/
etc. depois), trata-se de órgão público brasileiro legítimo. Casos como
``mda.gov.br.tripod.com`` permanecem rotulados como phishing porque
usam ``gov.br`` apenas como prefixo enganoso.

Saídas:
  - ``lista_validacao.csv`` atualizado in-place com novos rótulos.
  - ``resultados/validacao_formal_corrigido.json`` com métricas
    recalculadas a partir dos mesmos resultados de inferência.
  - Imprime a comparação antes/depois das métricas.
"""

import csv
import json
import math
import statistics
from dataclasses import dataclass, asdict
from pathlib import Path

# URLs identificadas como falsos rótulos (orgão público BR legítimo,
# foi inserido na blacklist por engano upstream).
URLS_A_CORRIGIR = {
    "http://camaraeugeniodecastro.rs.gov.br",
    "http://camarairacema.ce.gov.br",
    "http://crecise.gov.br",
    "http://camaraareial.pb.gov.br",
    "http://cmnovacanaapaulista.sp.gov.br",
    "http://licitacao.rc.sp.gov.br",
    "http://carloschagas.mg.gov.br",
    "http://camaradearaua.se.gov.br",
    "http://www.pittur.pitimbu.pb.gov.br",
    "http://brejogrande.se.gov.br",
    "http://cmsjm.rj.gov.br",
    "http://educacao.barretos.sp.gov.br",
    "http://camaradecorregodoouro.go.gov.br",
}

ROOT = Path(__file__).parent
LISTA_PATH = ROOT / "lista_validacao.csv"
JSON_IN = ROOT / "resultados" / "validacao_formal.json"
JSON_OUT = ROOT / "resultados" / "validacao_formal_corrigido.json"


@dataclass
class Metrics:
    model_name: str
    n_total: int
    n_legit: int
    n_phish: int
    tp: int
    fp: int
    tn: int
    fn: int
    accuracy: float
    precision: float
    recall: float
    f1: float
    fpr: float
    mcc: float
    latency_p50: float
    latency_p95: float
    latency_p99: float
    latency_mean: float


def recompute(model_name: str, results: list[dict]) -> Metrics:
    """Recalcula métricas a partir dos resultados individuais
    (com novo expected_phishing já corrigido)."""
    tp = sum(1 for r in results if r["expected_phishing"] and r["predicted_phishing"])
    fn = sum(1 for r in results if r["expected_phishing"] and not r["predicted_phishing"])
    fp = sum(1 for r in results if not r["expected_phishing"] and r["predicted_phishing"])
    tn = sum(1 for r in results if not r["expected_phishing"] and not r["predicted_phishing"])

    n_total = len(results)
    n_phish = tp + fn
    n_legit = tn + fp

    accuracy = (tp + tn) / n_total if n_total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    num = (tp * tn) - (fp * fn)
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (num / den) if den else 0.0

    lats = [r["inference_ms"] for r in results]
    p50 = statistics.median(lats) if lats else 0.0
    p95 = statistics.quantiles(lats, n=100)[94] if len(lats) >= 100 else (max(lats) if lats else 0.0)
    p99 = statistics.quantiles(lats, n=100)[98] if len(lats) >= 100 else (max(lats) if lats else 0.0)
    mean_lat = statistics.mean(lats) if lats else 0.0

    return Metrics(
        model_name=model_name,
        n_total=n_total, n_legit=n_legit, n_phish=n_phish,
        tp=tp, fp=fp, tn=tn, fn=fn,
        accuracy=accuracy, precision=precision, recall=recall,
        f1=f1, fpr=fpr, mcc=mcc,
        latency_p50=p50, latency_p95=p95, latency_p99=p99, latency_mean=mean_lat,
    )


def corrigir_lista_csv() -> int:
    """Atualiza in-place o lista_validacao.csv com os novos rótulos."""
    rows = []
    n_alterados = 0
    with LISTA_PATH.open("r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        fieldnames = reader.fieldnames
        for row in reader:
            if row["url"] in URLS_A_CORRIGIR and row["label"] == "phishing":
                row["label"] = "legitimate"
                row["fonte"] = "blacklist-real-revertida"
                row["nota"] = "orgao-publico-legitimo (blacklist upstream errada)"
                n_alterados += 1
            rows.append(row)

    with LISTA_PATH.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return n_alterados


def aplicar_correcao_resultados(resultados: list[dict]) -> tuple[list[dict], int]:
    """Aplica a correção no expected_phishing dos resultados individuais."""
    n_corrigidos = 0
    novos = []
    for r in resultados:
        if r["url"] in URLS_A_CORRIGIR and r["expected_phishing"] is True:
            r2 = dict(r)
            r2["expected_phishing"] = False  # agora é legítima
            novos.append(r2)
            n_corrigidos += 1
        else:
            novos.append(r)
    return novos, n_corrigidos


def collect_fps_fns(results: list[dict]) -> tuple[list[dict], list[dict]]:
    fps = sorted(
        [{"url": r["url"], "p": round(r["probability_phishing"], 4)}
         for r in results if not r["expected_phishing"] and r["predicted_phishing"]],
        key=lambda x: -x["p"],
    )
    fns = sorted(
        [{"url": r["url"], "p": round(r["probability_phishing"], 4)}
         for r in results if r["expected_phishing"] and not r["predicted_phishing"]],
        key=lambda x: x["p"],
    )
    return fps, fns


def imprimir_comparacao(antigo: dict, novo: Metrics, label: str) -> None:
    print(f"\n--- {label} ---")
    print(f"  {'Métrica':<22} {'antes':>12} {'depois':>12} {'Δ':>10}")
    pares = [
        ("TP",        antigo["tp"],         novo.tp),
        ("FP",        antigo["fp"],         novo.fp),
        ("TN",        antigo["tn"],         novo.tn),
        ("FN",        antigo["fn"],         novo.fn),
        ("n_legit",   antigo["n_legit"],    novo.n_legit),
        ("n_phish",   antigo["n_phish"],    novo.n_phish),
    ]
    for nome, a, d in pares:
        sinal = "+" if (d - a) > 0 else ""
        print(f"  {nome:<22} {a:>12} {d:>12} {sinal}{d-a:>9}")
    pares_f = [
        ("Acurácia",  antigo["accuracy"],   novo.accuracy),
        ("Precisão",  antigo["precision"],  novo.precision),
        ("Revocação", antigo["recall"],     novo.recall),
        ("F1",        antigo["f1"],         novo.f1),
        ("FPR",       antigo["fpr"],        novo.fpr),
        ("MCC",       antigo["mcc"],        novo.mcc),
    ]
    for nome, a, d in pares_f:
        delta = d - a
        sinal = "+" if delta > 0 else ""
        print(f"  {nome:<22} {a:>12.4f} {d:>12.4f} {sinal}{delta:>+9.4f}")


def main():
    print(f"Carregando {JSON_IN}...")
    with JSON_IN.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)

    print(f"\nCorreção de rótulos no CSV ({len(URLS_A_CORRIGIR)} URLs alvo):")
    n_csv = corrigir_lista_csv()
    print(f"  {n_csv} linhas atualizadas em {LISTA_PATH.name}.")

    print(f"\nRecalculando métricas com correção aplicada...")
    metricas_novas = {}
    resultados_novos = {}
    for variant in ("url_whois", "multimodal"):
        results_orig = payload["resultados_individuais"][variant]
        results_corr, n = aplicar_correcao_resultados(results_orig)
        print(f"  [{variant}] {n} resultados re-rotulados (phishing → legitimate).")
        m = recompute(payload["metricas"][variant]["model_name"], results_corr)
        metricas_novas[variant] = m
        resultados_novos[variant] = results_corr
        imprimir_comparacao(payload["metricas"][variant], m, variant)

    # Persistir nova versão completa
    novo_payload = {
        "configuracao": {
            **payload["configuracao"],
            "correcao_rotulos_aplicada": True,
            "n_urls_recategorizadas": n_csv,
            "criterio_recategorizacao": (
                "URLs *.gov.br/leg.br/jus.br que terminam exatamente "
                "no TLD oficial brasileiro foram reclassificadas como "
                "legitimate. URLs com gov.br apenas como subdomínio "
                "enganoso (ex.: mda.gov.br.tripod.com) permaneceram "
                "como phishing."
            ),
        },
        "metricas": {
            variant: asdict(m) for variant, m in metricas_novas.items()
        },
        "resultados_individuais": resultados_novos,
    }
    # Re-popular falsos_positivos / falsos_negativos
    for variant, results in resultados_novos.items():
        fps, fns = collect_fps_fns(results)
        novo_payload["metricas"][variant]["falsos_positivos"] = fps
        novo_payload["metricas"][variant]["falsos_negativos"] = fns

    JSON_OUT.parent.mkdir(parents=True, exist_ok=True)
    with JSON_OUT.open("w", encoding="utf-8") as fh:
        json.dump(novo_payload, fh, indent=2, ensure_ascii=False)
    print(f"\nMétricas corrigidas salvas em {JSON_OUT}")


if __name__ == "__main__":
    main()
