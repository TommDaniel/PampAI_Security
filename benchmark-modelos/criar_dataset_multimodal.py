"""
criar_dataset_multimodal.py
===========================
Monta um dataset unificado combinando:
  1. URLs + labels do dataset_phishing_brasileiro.csv (660k amostras)
  2. Features WHOIS do whois_cache.json (~5.8k domínios)
  3. Features de URL/domínio do GregaVrbancic/Phishing-Dataset (88k amostras)

Saída: dataset_multimodal.csv
  - Colunas: url, label, text_input (texto formatado para transformers)
  - O text_input serializa URL + WHOIS + features extras como tokens estruturados

O texto de entrada para os transformers segue o formato:
  [URL] <url> [AGE] 365d [REG] GoDaddy [WHOIS] found [EXTRA] redirects=0 tls=1 ...

Uso:
  python criar_dataset_multimodal.py
"""

import os
import json
import math
import hashlib
from urllib.parse import urlparse

import pandas as pd
import numpy as np
import tldextract

# ============================================================
# Configuração
# ============================================================
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
BR_CSV      = os.path.join(SCRIPT_DIR, "dataset_phishing_brasileiro.csv")
WHOIS_JSON  = os.path.join(SCRIPT_DIR, "..", "phishing-api", "model", "whois_cache.json")
DOM_URL     = "https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_full.csv"
DOM_LOCAL   = os.path.join(SCRIPT_DIR, "grega_phishing_dom.csv")
OUTPUT_CSV  = os.path.join(SCRIPT_DIR, "dataset_multimodal.csv")
RANDOM_STATE = 42

# Features do GregaVrbancic que vamos incluir (as mais relevantes para phishing)
GREGA_FEATURES = [
    "qty_redirects",
    "length_url",
    "domain_length",
    "qty_dot_url",
    "qty_hyphen_url",
    "qty_slash_url",
    "qty_at_url",
    "qty_params",
    "url_shortened",
    "tls_ssl_certificate",
    "time_domain_activation",
    "time_domain_expiration",
    "qty_mx_servers",
    "qty_nameservers",
    "domain_google_index",
    "domain_spf",
    "domain_in_ip",
    "qty_vowels_domain",
    "server_client_domain",
    "email_in_url",
]


def extract_domain(url: str) -> str:
    """Extrai domínio registrável de uma URL."""
    try:
        ext = tldextract.extract(url)
        if ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return ext.domain
    except Exception:
        return ""


def load_whois(path: str) -> dict:
    """Carrega cache WHOIS."""
    path = os.path.normpath(path)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            cache = json.load(f)
        found = sum(1 for v in cache.values() if v.get("status") == "found")
        print(f"[WHOIS] {len(cache):,} domínios ({found:,} com dados)")
        return cache
    print(f"[WHOIS] Arquivo não encontrado: {path}")
    return {}


def load_grega_dataset(url: str, local_path: str) -> pd.DataFrame:
    """Baixa ou carrega o dataset GregaVrbancic com features de URL/domínio."""
    if os.path.exists(local_path):
        print(f"[GREGA] Carregando cache local: {local_path}")
        df = pd.read_csv(local_path)
    else:
        print(f"[GREGA] Baixando de {url}...")
        df = pd.read_csv(url)
        df.to_csv(local_path, index=False)
        print(f"[GREGA] Salvo em: {local_path}")

    print(f"[GREGA] {len(df):,} amostras, {len(df.columns)} colunas")
    print(f"[GREGA] Phishing: {df['phishing'].mean():.1%}")

    # Verificar quais features existem
    available = [f for f in GREGA_FEATURES if f in df.columns]
    missing   = [f for f in GREGA_FEATURES if f not in df.columns]
    if missing:
        print(f"[GREGA] Features não encontradas (ignoradas): {missing}")
    print(f"[GREGA] Features disponíveis: {len(available)}/{len(GREGA_FEATURES)}")

    return df, available


def format_whois(url: str, cache: dict) -> str:
    """Formata metadados WHOIS como tokens de texto."""
    domain = extract_domain(url)
    info = cache.get(domain, {})
    if info.get("status") == "found":
        age = info.get("domain_age_days", "?")
        reg = str(info.get("registrar", "unk"))[:25].strip()
        expire = info.get("days_to_expire", "?")
        return f"[AGE] {age}d [REG] {reg} [EXPIRE] {expire}d [WHOIS] found"
    return "[WHOIS] unknown"


def format_extra(row: pd.Series, features: list) -> str:
    """Formata features extras do GregaVrbancic como tokens de texto."""
    parts = []
    for feat in features:
        val = row.get(feat, None)
        if val is not None and not (isinstance(val, float) and math.isnan(val)):
            # Abreviar nome do feature para caber no contexto do transformer
            short = (feat
                     .replace("qty_", "")
                     .replace("_url", "")
                     .replace("domain_", "dom_")
                     .replace("server_client_domain", "srv_client")
                     .replace("tls_ssl_certificate", "tls")
                     .replace("time_domain_activation", "dom_age")
                     .replace("time_domain_expiration", "dom_expire")
                     .replace("url_shortened", "shortened")
                     .replace("email_in_url", "email"))
            parts.append(f"{short}={int(val)}")
    if parts:
        return "[EXTRA] " + " ".join(parts)
    return "[EXTRA] none"


def build_dataset():
    """Pipeline principal de construção do dataset."""

    # ── 1. Dataset brasileiro (URLs + labels) ──────────────────────
    print("=" * 65)
    print("1. Carregando dataset brasileiro...")
    print("=" * 65)
    br_df = pd.read_csv(BR_CSV, encoding="utf-8", usecols=["url", "label"])
    print(f"   {len(br_df):,} amostras | Phishing: {br_df['label'].mean():.1%}")

    # ── 2. WHOIS cache ─────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("2. Carregando WHOIS cache...")
    print("=" * 65)
    whois = load_whois(WHOIS_JSON)

    # ── 3. Dataset GregaVrbancic (features de URL/domínio) ─────────
    print("\n" + "=" * 65)
    print("3. Carregando dataset GregaVrbancic...")
    print("=" * 65)
    grega_df, grega_feats = load_grega_dataset(DOM_URL, DOM_LOCAL)

    # ── 4. Preparar dataset GregaVrbancic ─────────────────────────
    # O dataset Grega NÃO tem coluna 'url' — usamos um ID sintético
    print("\n" + "=" * 65)
    print("4. Processando dataset GregaVrbancic...")
    print("=" * 65)
    grega_records = []
    for idx, row in grega_df.iterrows():
        synth_url = f"grega_sample_{idx}"
        label = int(row.get("phishing", 0))
        extra_txt = format_extra(row, grega_feats)
        text_input = f"[URL] {synth_url} [WHOIS] unknown {extra_txt}"
        grega_records.append({"url": synth_url, "label": label, "text_input": text_input, "source": "grega"})

    grega_processed = pd.DataFrame(grega_records)
    print(f"   GregaVrbancic processado: {len(grega_processed):,} amostras")

    # ── 5. Preparar dataset brasileiro (URL + WHOIS) ──────────────
    print("\n" + "=" * 65)
    print("5. Processando dataset brasileiro (URL + WHOIS)...")
    print("=" * 65)
    br_records = []
    for _, row in br_df.iterrows():
        url = str(row["url"])
        label = int(row["label"])
        whois_txt = format_whois(url, whois)
        text_input = f"[URL] {url} {whois_txt} [EXTRA] none"
        br_records.append({"url": url, "label": label, "text_input": text_input, "source": "brasileiro"})

    br_processed = pd.DataFrame(br_records)
    print(f"   Brasileiro processado: {len(br_processed):,} amostras")

    # ── 6. Combinar e balancear ────────────────────────────────────
    print("\n" + "=" * 65)
    print("6. Combinando datasets...")
    print("=" * 65)

    combined = pd.concat([grega_processed, br_processed], ignore_index=True)

    # Remover duplicatas por URL (apenas entre amostras com URLs reais)
    before = len(combined)
    combined = combined.drop_duplicates(subset=["url"], keep="first")
    print(f"   Duplicatas removidas: {before - len(combined):,}")
    print(f"   Total combinado: {len(combined):,}")
    print(f"   GregaVrbancic: {(combined['source'] == 'grega').sum():,}")
    print(f"   Brasileiro: {(combined['source'] == 'brasileiro').sum():,}")
    print(f"   Phishing: {combined['label'].mean():.1%}")

    # Verificar cobertura WHOIS
    whois_found = combined["text_input"].str.contains(r"\[WHOIS\] found", regex=True).sum()
    print(f"   Com WHOIS: {whois_found:,} ({whois_found/len(combined):.1%})")

    # ── 7. Shuffle e salvar ────────────────────────────────────────
    print("\n" + "=" * 65)
    print("7. Salvando dataset final...")
    print("=" * 65)

    combined = combined.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)
    combined.to_csv(OUTPUT_CSV, index=False, encoding="utf-8")
    print(f"   Salvo em: {OUTPUT_CSV}")
    print(f"   Tamanho: {os.path.getsize(OUTPUT_CSV) / 1e6:.1f} MB")

    # Exemplos
    print("\n" + "=" * 65)
    print("Exemplos de text_input:")
    print("=" * 65)
    for source in ["grega", "brasileiro"]:
        sample = combined[combined["source"] == source].iloc[0]
        print(f"\n  [{source}] label={sample['label']}")
        print(f"  {sample['text_input'][:200]}...")

    # Estatísticas finais
    print("\n" + "=" * 65)
    print("Estatísticas finais")
    print("=" * 65)
    lens = combined["text_input"].str.len()
    print(f"  Comprimento text_input — P50: {lens.median():.0f} | P95: {lens.quantile(0.95):.0f} | Max: {lens.max():.0f}")
    print(f"  Total amostras:  {len(combined):,}")
    print(f"  Labels — 0 (legítimo): {(combined['label']==0).sum():,} | 1 (phishing): {(combined['label']==1).sum():,}")

    return combined


if __name__ == "__main__":
    build_dataset()
