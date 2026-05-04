"""
validacao_formal.py
===================

Validação formal e comparativa entre as variantes
**DomURLs-BERT URL+WHOIS** (modelo principal adotado) e **DomURLs-BERT
multimodal** (avaliado e não adotado), seguindo o desenho metodológico
solicitado pelo orientador:

    "Lista pré-registrada com medição automática de Verdadeiros
    Positivos, Falsos Positivos e latência fim-a-fim."

Este script é a contrapartida formal das rodadas qualitativas
``validacao_modelo.json`` (62 URLs) e ``validacao_cascata.json`` (101
URLs) já existentes.  Ele resolve a pendência metodológica reconhecida
em §5.5 e §5.6 do capítulo de Resultados — onde o trabalho declara que
uma rodada formal equivalente para o multimodal *não foi executada*.

Uso típico (rodado no PC de teste do autor):

    python validacao_formal.py \\
        --model-urlonly /caminho/para/TCC-Finetuning-DomURLs-BERT/modelo-final \\
        --model-multimodal /caminho/para/models/DomURLs-BERT-multimodal \\
        --lista lista_validacao.csv \\
        --output resultados/validacao_formal.json

Os modelos são carregados diretamente via ``transformers``; a API da
extensão NÃO é envolvida, eliminando latência de rede e variabilidade
do processo de inferência embutido na FastAPI.  A latência reportada
corresponde ao tempo de ``forward`` do modelo apenas (URL → veredicto),
medido em ms com ``time.perf_counter``.  Métricas de coleta de WHOIS são
relatadas separadamente.

Decisão metodológica explícita: ambos os modelos recebem exatamente o
mesmo ``text_input`` no formato ``[URL] {url} {whois_txt} [EXTRA] none``,
isolando a diferença entre os dois modelos exclusivamente nos pesos
treinados.  Isto reflete a condição de uso real da extensão, na qual
features tabulares do dataset GregaVrbancic não estão disponíveis.

Saídas:
  - ``resultados/validacao_formal.json``: resultados detalhados por URL
    e por modelo, com métricas agregadas e listagem de falsos positivos.
  - Saída padrão: tabela comparativa formatada para registro no TCC.
"""

import argparse
import csv
import json
import math
import socket
import statistics
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------

DEFAULT_THRESHOLD = 0.65
DEFAULT_MAX_LENGTH = 192
WHOIS_TIMEOUT_SECONDS = 8


# ---------------------------------------------------------------------
# Estruturas de dados
# ---------------------------------------------------------------------

@dataclass
class UrlSample:
    """Uma URL da lista pré-registrada."""

    url: str
    label: str  # "legitimate" ou "phishing"
    fonte: str
    nota: str

    @property
    def expected_phishing(self) -> bool:
        return self.label == "phishing"


@dataclass
class InferenceResult:
    """Saída de uma única predição."""

    url: str
    expected_phishing: bool
    predicted_phishing: bool
    probability_phishing: float
    inference_ms: float


@dataclass
class ModelMetrics:
    """Métricas agregadas para um modelo."""

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
    falsos_positivos: list = field(default_factory=list)
    falsos_negativos: list = field(default_factory=list)


# ---------------------------------------------------------------------
# Coleta de WHOIS (com cache para não re-consultar entre execuções)
# ---------------------------------------------------------------------

def extract_domain(url: str) -> str:
    """Extrai o domínio raiz de uma URL para consulta WHOIS."""
    if not url.startswith("http"):
        url = f"http://{url}"
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def query_whois(domain: str) -> dict:
    """Consulta WHOIS uma única vez para um domínio.

    Retorna dict com chaves ``status`` (``found``/``unknown``) e, quando
    encontrado, ``domain_age_days``, ``registrar`` e ``days_to_expire``.
    Erros e timeouts são tratados retornando ``{"status": "unknown"}``.
    """
    try:
        import whois  # type: ignore
    except ImportError:
        return {"status": "unknown", "error": "lib python-whois não instalada"}

    try:
        record = whois.whois(domain)  # type: ignore[attr-defined]
        if not record or not record.creation_date:
            return {"status": "unknown"}

        creation = record.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        expiration = record.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]

        from datetime import datetime
        now = datetime.utcnow()
        age_days = (now - creation).days if creation else None
        days_to_expire = (expiration - now).days if expiration else None
        registrar = str(record.registrar or "unk")[:25]
        return {
            "status": "found",
            "domain_age_days": int(age_days) if age_days and age_days > 0 else None,
            "days_to_expire": int(days_to_expire) if days_to_expire is not None else None,
            "registrar": registrar.strip(),
        }
    except Exception:
        return {"status": "unknown"}


def format_whois(whois_info: dict) -> str:
    """Formata WHOIS no template do treinamento."""
    if whois_info.get("status") != "found":
        return "[WHOIS] unknown"
    age = whois_info.get("domain_age_days", "?")
    reg = whois_info.get("registrar", "unk")
    expire = whois_info.get("days_to_expire", "?")
    return f"[AGE] {age}d [REG] {reg} [EXPIRE] {expire}d [WHOIS] found"


def load_or_init_cache(cache_path: Path) -> dict:
    if cache_path.exists():
        with cache_path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def save_cache(cache_path: Path, cache: dict) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with cache_path.open("w", encoding="utf-8") as fh:
        json.dump(cache, fh, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------
# Inferência
# ---------------------------------------------------------------------

def build_text_input(url: str, whois_txt: str) -> str:
    """Monta o text_input no formato exato usado no treinamento."""
    return f"[URL] {url} {whois_txt} [EXTRA] none"


def load_model(model_path: str):
    """Carrega tokenizer + modelo de um diretório local."""
    import torch  # noqa: F401  (verificação de disponibilidade)
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    print(f"   Carregando modelo de {model_path}...")
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForSequenceClassification.from_pretrained(model_path)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()
    print(f"   Modelo carregado (device={device}).")
    return tokenizer, model, device


def predict(tokenizer, model, device, text_input: str, max_length: int) -> tuple[float, float]:
    """Roda uma inferência. Retorna (P(phishing), latência_ms)."""
    import torch

    t0 = time.perf_counter()
    inputs = tokenizer(
        text_input,
        return_tensors="pt",
        truncation=True,
        max_length=max_length,
        padding=True,
    )
    inputs = {k: v.to(device) for k, v in inputs.items()}
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=-1)
    p_phish = probs[0][1].item()
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return p_phish, elapsed_ms


# ---------------------------------------------------------------------
# Métricas agregadas
# ---------------------------------------------------------------------

def compute_metrics(model_name: str, results: list[InferenceResult]) -> ModelMetrics:
    """Calcula TP/FP/TN/FN, P/R/F1/FPR/MCC e percentis de latência."""
    tp = sum(1 for r in results if r.expected_phishing and r.predicted_phishing)
    fn = sum(1 for r in results if r.expected_phishing and not r.predicted_phishing)
    fp = sum(1 for r in results if not r.expected_phishing and r.predicted_phishing)
    tn = sum(1 for r in results if not r.expected_phishing and not r.predicted_phishing)

    n_total = len(results)
    n_phish = tp + fn
    n_legit = tn + fp

    accuracy = (tp + tn) / n_total if n_total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    mcc_num = (tp * tn) - (fp * fn)
    mcc_den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (mcc_num / mcc_den) if mcc_den else 0.0

    lats = [r.inference_ms for r in results]
    p50 = statistics.median(lats) if lats else 0.0
    p95 = statistics.quantiles(lats, n=100)[94] if len(lats) >= 100 else (max(lats) if lats else 0.0)
    p99 = statistics.quantiles(lats, n=100)[98] if len(lats) >= 100 else (max(lats) if lats else 0.0)
    mean_lat = statistics.mean(lats) if lats else 0.0

    falsos_positivos = sorted(
        [{"url": r.url, "p": round(r.probability_phishing, 4)}
         for r in results if not r.expected_phishing and r.predicted_phishing],
        key=lambda x: -x["p"],
    )
    falsos_negativos = sorted(
        [{"url": r.url, "p": round(r.probability_phishing, 4)}
         for r in results if r.expected_phishing and not r.predicted_phishing],
        key=lambda x: x["p"],
    )

    return ModelMetrics(
        model_name=model_name,
        n_total=n_total,
        n_legit=n_legit,
        n_phish=n_phish,
        tp=tp, fp=fp, tn=tn, fn=fn,
        accuracy=accuracy, precision=precision, recall=recall, f1=f1, fpr=fpr, mcc=mcc,
        latency_p50=p50, latency_p95=p95, latency_p99=p99, latency_mean=mean_lat,
        falsos_positivos=falsos_positivos,
        falsos_negativos=falsos_negativos,
    )


# ---------------------------------------------------------------------
# Pipeline principal
# ---------------------------------------------------------------------

def load_lista(csv_path: Path) -> list[UrlSample]:
    samples = []
    with csv_path.open("r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            samples.append(UrlSample(
                url=row["url"].strip(),
                label=row["label"].strip(),
                fonte=row.get("fonte", "").strip(),
                nota=row.get("nota", "").strip(),
            ))
    return samples


def run_model(
    model_label: str,
    model_path: str,
    samples: list[UrlSample],
    text_inputs_by_url: dict[str, str],
    threshold: float,
    max_length: int,
) -> tuple[ModelMetrics, list[InferenceResult]]:
    """Carrega um modelo, roda inferência sobre todas as amostras e devolve métricas."""
    print(f"\n[{model_label}] preparando modelo...")
    tokenizer, model, device = load_model(model_path)

    results: list[InferenceResult] = []
    print(f"[{model_label}] iniciando inferência sobre {len(samples)} URLs...")
    for i, sample in enumerate(samples, 1):
        text = text_inputs_by_url[sample.url]
        p_phish, elapsed_ms = predict(tokenizer, model, device, text, max_length)
        predicted_phishing = p_phish >= threshold
        results.append(InferenceResult(
            url=sample.url,
            expected_phishing=sample.expected_phishing,
            predicted_phishing=predicted_phishing,
            probability_phishing=p_phish,
            inference_ms=elapsed_ms,
        ))
        if i % 25 == 0 or i == len(samples):
            print(f"   [{model_label}] {i}/{len(samples)} amostras processadas...")

    metrics = compute_metrics(model_label, results)
    return metrics, results


def collect_whois_for_all(
    samples: list[UrlSample],
    cache_path: Path,
    no_whois: bool,
) -> dict[str, str]:
    """Coleta WHOIS de todos os domínios (com cache); retorna text_input por URL."""
    cache = load_or_init_cache(cache_path)
    text_inputs: dict[str, str] = {}

    print(f"\nColeta de WHOIS ({len(samples)} URLs; cache em {cache_path}):")
    for i, sample in enumerate(samples, 1):
        domain = extract_domain(sample.url)
        if no_whois:
            whois_txt = "[WHOIS] unknown"
        else:
            if domain not in cache:
                cache[domain] = query_whois(domain)
                save_cache(cache_path, cache)
            whois_txt = format_whois(cache[domain])

        text_inputs[sample.url] = build_text_input(sample.url, whois_txt)
        if i % 25 == 0 or i == len(samples):
            n_found = sum(1 for d in cache.values() if d.get("status") == "found")
            print(f"   {i}/{len(samples)} URLs preparadas ({n_found} domínios com WHOIS coletado).")

    return text_inputs


# ---------------------------------------------------------------------
# Saída formatada
# ---------------------------------------------------------------------

def print_comparison_table(m1: ModelMetrics, m2: ModelMetrics) -> None:
    """Imprime tabela comparativa entre dois modelos."""
    rows = [
        ("URLs avaliadas", str(m1.n_total), str(m2.n_total)),
        ("    Legítimas", str(m1.n_legit), str(m2.n_legit)),
        ("    Phishing",  str(m1.n_phish), str(m2.n_phish)),
        ("Verdadeiros Positivos (VP)", str(m1.tp), str(m2.tp)),
        ("Falsos Positivos (FP)", str(m1.fp), str(m2.fp)),
        ("Verdadeiros Negativos (VN)", str(m1.tn), str(m2.tn)),
        ("Falsos Negativos (FN)", str(m1.fn), str(m2.fn)),
        ("Acurácia",  f"{m1.accuracy:.4f}",  f"{m2.accuracy:.4f}"),
        ("Precisão",  f"{m1.precision:.4f}", f"{m2.precision:.4f}"),
        ("Revocação", f"{m1.recall:.4f}",    f"{m2.recall:.4f}"),
        ("F1",        f"{m1.f1:.4f}",        f"{m2.f1:.4f}"),
        ("FPR",       f"{m1.fpr*100:.2f}%",  f"{m2.fpr*100:.2f}%"),
        ("MCC",       f"{m1.mcc:.4f}",       f"{m2.mcc:.4f}"),
        ("Latência média (ms)", f"{m1.latency_mean:.2f}", f"{m2.latency_mean:.2f}"),
        ("Latência P50 (ms)",   f"{m1.latency_p50:.2f}",  f"{m2.latency_p50:.2f}"),
        ("Latência P95 (ms)",   f"{m1.latency_p95:.2f}",  f"{m2.latency_p95:.2f}"),
        ("Latência P99 (ms)",   f"{m1.latency_p99:.2f}",  f"{m2.latency_p99:.2f}"),
    ]

    col1 = max(30, max(len(r[0]) for r in rows) + 2)
    col2 = max(len(m1.model_name), max(len(r[1]) for r in rows)) + 4
    col3 = max(len(m2.model_name), max(len(r[2]) for r in rows)) + 4

    print("\n" + "=" * (col1 + col2 + col3))
    print("VALIDAÇÃO FORMAL — COMPARAÇÃO ENTRE MODELOS")
    print("=" * (col1 + col2 + col3))
    print(f"{'Métrica':<{col1}}{m1.model_name:<{col2}}{m2.model_name:<{col3}}")
    print("-" * (col1 + col2 + col3))
    for nome, v1, v2 in rows:
        print(f"{nome:<{col1}}{v1:<{col2}}{v2:<{col3}}")
    print("=" * (col1 + col2 + col3))


def print_false_positives(metrics: ModelMetrics, max_show: int = 10) -> None:
    """Imprime URLs legítimas que o modelo classificou como phishing."""
    print(f"\n[{metrics.model_name}] Top falsos positivos (legítimas marcadas como phishing):")
    if not metrics.falsos_positivos:
        print("   (nenhum)")
        return
    for i, fp in enumerate(metrics.falsos_positivos[:max_show], 1):
        print(f"   {i:2d}. p={fp['p']:.3f}  {fp['url']}")
    if len(metrics.falsos_positivos) > max_show:
        print(f"   ... e mais {len(metrics.falsos_positivos) - max_show} URLs (ver JSON).")


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Validação formal: DomURLs-BERT URL+WHOIS vs multimodal.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--model-urlonly", required=True,
                        help="Caminho local para o modelo URL+WHOIS (TCC-Finetuning-DomURLs-BERT/modelo-final).")
    parser.add_argument("--model-multimodal", required=True,
                        help="Caminho local para o modelo multimodal (DomURLs-BERT-multimodal).")
    parser.add_argument("--lista", default=str(Path(__file__).parent / "lista_validacao.csv"),
                        help="CSV com colunas url,label,fonte,nota.")
    parser.add_argument("--output", default=str(Path(__file__).parent / "resultados" / "validacao_formal.json"),
                        help="Caminho do JSON de saída.")
    parser.add_argument("--whois-cache", default=str(Path(__file__).parent / "whois_cache.json"),
                        help="Caminho do cache de WHOIS (criado/atualizado automaticamente).")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help=f"Limiar de classificação (default {DEFAULT_THRESHOLD}).")
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH,
                        help=f"Comprimento máximo do tokenizer (default {DEFAULT_MAX_LENGTH}).")
    parser.add_argument("--no-whois", action="store_true",
                        help="Pula coleta WHOIS e usa '[WHOIS] unknown' para todas as URLs.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    lista_path = Path(args.lista)
    if not lista_path.exists():
        print(f"Erro: lista de URLs não encontrada em {lista_path}", file=sys.stderr)
        return 1

    samples = load_lista(lista_path)
    print(f"Lista carregada: {len(samples)} URLs ({sum(1 for s in samples if not s.expected_phishing)} legítimas, "
          f"{sum(1 for s in samples if s.expected_phishing)} phishing).")

    # Coleta WHOIS uma única vez (cacheada) para isolar latência da inferência.
    text_inputs = collect_whois_for_all(
        samples,
        cache_path=Path(args.whois_cache),
        no_whois=args.no_whois,
    )

    metrics_url, results_url = run_model(
        "URL+WHOIS",
        args.model_urlonly,
        samples, text_inputs,
        threshold=args.threshold, max_length=args.max_length,
    )

    metrics_mm, results_mm = run_model(
        "Multimodal",
        args.model_multimodal,
        samples, text_inputs,
        threshold=args.threshold, max_length=args.max_length,
    )

    # Saída formatada
    print_comparison_table(metrics_url, metrics_mm)
    print_false_positives(metrics_url)
    print_false_positives(metrics_mm)

    # Persistência completa em JSON
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "configuracao": {
            "lista": str(lista_path),
            "threshold": args.threshold,
            "max_length": args.max_length,
            "no_whois": args.no_whois,
            "model_urlonly_path": args.model_urlonly,
            "model_multimodal_path": args.model_multimodal,
            "host": socket.gethostname(),
            "executado_em_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "metricas": {
            "url_whois": asdict(metrics_url),
            "multimodal": asdict(metrics_mm),
        },
        "resultados_individuais": {
            "url_whois": [asdict(r) for r in results_url],
            "multimodal": [asdict(r) for r in results_mm],
        },
    }
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    print(f"\nResultados completos salvos em {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
