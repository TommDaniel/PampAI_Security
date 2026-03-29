"""
Coletor de Blacklist de Phishing/Malware
==========================================
Baixa listas públicas de URLs e domínios maliciosos de múltiplas fontes,
deduplica e gera dois arquivos para uso na extensão:

  blacklist.csv   — para auditoria e controle (url, source, tipo)
  blacklist.json  — array de domínios para bundlar na extensão (lookup O(1))

Fontes usadas:
  - OpenPhish        (feed de phishing atualizado)
  - PhishStats       (CSV bulk, phishing com score)
  - URLhaus (Abuse.ch) (URLs de malware/botnet)
  - PhishTank        (CSV público de phishing verificado)
  - Phishing.Database (GitHub — lista comunitária)

Uso:
  pip install requests pandas
  python coletar_blacklist.py

Depois copie o blacklist.json para:
  ../extensao-phishing/assets/blacklist.json
"""

import requests
import pandas as pd
import json
import re
import time
from io import StringIO
from urllib.parse import urlparse

OUTPUT_CSV  = "blacklist.csv"
OUTPUT_JSON = "blacklist.json"

HEADERS = {
    "User-Agent": "TCC-Phishing-Research/1.0 (Academic Research; Phishing Blacklist)"
}

# ============================================================
# Helpers
# ============================================================

def extract_domain(url: str) -> str:
    """Extrai só o hostname de uma URL para lookup por domínio."""
    try:
        u = url.strip()
        if not u.startswith(("http://", "https://")):
            u = "http://" + u
        return urlparse(u).hostname or ""
    except Exception:
        return ""

def normalize_url(url: str) -> str:
    """Remove trailing slash e normaliza para minúsculas."""
    return url.strip().lower().rstrip("/")

# ============================================================
# Fontes
# ============================================================

def collect_openphish() -> list[dict]:
    """OpenPhish — feed público de phishing (sem auth, ~500 URLs)."""
    print("  [OpenPhish] Baixando feed...")
    try:
        r = requests.get("https://openphish.com/feed.txt", headers=HEADERS, timeout=30)
        if r.status_code != 200:
            print(f"    HTTP {r.status_code}")
            return []
        urls = [u.strip() for u in r.text.strip().split("\n") if u.strip()]
        result = [{"url": u, "domain": extract_domain(u), "source": "openphish", "type": "phishing"}
                  for u in urls]
        print(f"    -> {len(result)} URLs")
        return result
    except Exception as e:
        print(f"    Erro: {e}")
        return []


def collect_phishstats() -> list[dict]:
    """PhishStats CSV bulk — phishing com score de confiança."""
    print("  [PhishStats] Baixando CSV bulk...")
    try:
        r = requests.get(
            "https://phishstats.info/phish_score.csv",
            headers=HEADERS, timeout=120, stream=True
        )
        if r.status_code != 200:
            print(f"    HTTP {r.status_code}")
            return []

        lines = []
        for i, line in enumerate(r.iter_lines(decode_unicode=True)):
            if line and not line.startswith("#"):
                lines.append(line)
            if i > 200_000:
                break

        if len(lines) < 2:
            return []

        df = pd.read_csv(StringIO("\n".join(lines)), on_bad_lines="skip")

        # Encontrar coluna de URL
        url_col = next((c for c in df.columns if "url" in c.lower()), None)
        score_col = next((c for c in df.columns if "score" in c.lower()), None)
        if not url_col:
            print("    Coluna URL não encontrada")
            return []

        # Filtrar score >= 4 (mais confiável)
        if score_col:
            df = df[pd.to_numeric(df[score_col], errors="coerce").fillna(0) >= 4]

        result = []
        for _, row in df.iterrows():
            u = str(row[url_col]).strip()
            if u and u != "nan":
                result.append({
                    "url": u,
                    "domain": extract_domain(u),
                    "source": "phishstats",
                    "type": "phishing"
                })

        print(f"    -> {len(result)} URLs (score >= 4)")
        return result
    except Exception as e:
        print(f"    Erro: {e}")
        return []


def collect_urlhaus() -> list[dict]:
    """URLhaus (Abuse.ch) — URLs de malware e botnet ativas."""
    print("  [URLhaus] Baixando CSV de URLs online...")
    try:
        r = requests.get(
            "https://urlhaus.abuse.ch/downloads/csv_online/",
            headers=HEADERS, timeout=120
        )
        if r.status_code != 200:
            print(f"    HTTP {r.status_code}")
            return []

        lines = [l for l in r.text.split("\n") if l and not l.startswith("#")]
        df = pd.read_csv(StringIO("\n".join(lines)), on_bad_lines="skip")

        url_col = next((c for c in df.columns if "url" in c.lower()), None)
        if not url_col:
            return []

        result = []
        for _, row in df.iterrows():
            u = str(row[url_col]).strip()
            if u and u != "nan":
                result.append({
                    "url": u,
                    "domain": extract_domain(u),
                    "source": "urlhaus",
                    "type": "malware"
                })

        print(f"    -> {len(result)} URLs")
        return result
    except Exception as e:
        print(f"    Erro: {e}")
        return []


def collect_phishtank() -> list[dict]:
    """PhishTank — CSV público de phishing verificado pela comunidade."""
    print("  [PhishTank] Baixando CSV...")
    try:
        r = requests.get(
            "https://data.phishtank.com/data/online-valid.csv",
            headers=HEADERS, timeout=120
        )
        if r.status_code != 200:
            print(f"    HTTP {r.status_code} (PhishTank pode bloquear sem API key)")
            return []

        df = pd.read_csv(StringIO(r.text), usecols=["url"], on_bad_lines="skip")
        result = []
        for _, row in df.iterrows():
            u = str(row["url"]).strip()
            if u and u != "nan":
                result.append({
                    "url": u,
                    "domain": extract_domain(u),
                    "source": "phishtank",
                    "type": "phishing"
                })
        print(f"    -> {len(result)} URLs")
        return result
    except Exception as e:
        print(f"    Erro: {e}")
        return []


def collect_phishing_database() -> list[dict]:
    """
    Phishing.Database (GitHub — mitchellkrogza)
    Lista comunitária com dezenas de milhares de domínios de phishing.
    """
    print("  [Phishing.Database] Baixando lista de domínios do GitHub...")
    urls_result = []
    sources = [
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    ]
    for src in sources:
        try:
            r = requests.get(src, headers=HEADERS, timeout=60)
            if r.status_code != 200:
                continue
            entries = [l.strip() for l in r.text.split("\n") if l.strip() and not l.startswith("#")]
            for entry in entries:
                url = entry if entry.startswith("http") else "http://" + entry
                urls_result.append({
                    "url": url,
                    "domain": extract_domain(url),
                    "source": "phishing_database",
                    "type": "phishing"
                })
            time.sleep(0.5)
        except Exception as e:
            print(f"    Erro em {src}: {e}")

    print(f"    -> {len(urls_result)} entradas")
    return urls_result


# ============================================================
# Pipeline principal
# ============================================================

def main():
    print("=" * 60)
    print("  COLETOR DE BLACKLIST DE PHISHING/MALWARE")
    print("=" * 60)

    all_data = []

    sources = [
        collect_openphish,
        collect_phishtank,
        collect_phishstats,
        collect_urlhaus,
        collect_phishing_database,
    ]

    for func in sources:
        try:
            result = func()
            all_data.extend(result)
        except Exception as e:
            print(f"    FALHOU: {e}")
        print(f"  Subtotal acumulado: {len(all_data)}")

    print(f"\n[PROCESSANDO]")

    df = pd.DataFrame(all_data)
    df = df[df["url"].str.strip().astype(bool)]
    df["url_norm"] = df["url"].apply(normalize_url)
    df = df.drop_duplicates(subset=["url_norm"])
    df = df.drop(columns=["url_norm"])
    df = df[df["domain"].str.strip().astype(bool)]

    print(f"  Total após deduplicação: {len(df):,}")
    print(f"\n  Por fonte:")
    for src, cnt in df["source"].value_counts().items():
        print(f"    {src}: {cnt:,}")
    print(f"\n  Por tipo:")
    for t, cnt in df["type"].value_counts().items():
        print(f"    {t}: {cnt:,}")

    # ---- Salvar CSV ----
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"\n  CSV salvo: {OUTPUT_CSV} ({len(df):,} entradas)")

    # ---- Salvar JSON (só domínios, para a extensão) ----
    # Usa domínios únicos — a extensão faz lookup pelo hostname da URL visitada
    domains = sorted(df["domain"].dropna().unique().tolist())
    domains = [d for d in domains if d]  # remove vazios

    with open(OUTPUT_JSON, "w") as f:
        json.dump(domains, f, separators=(",", ":"))

    print(f"  JSON salvo: {OUTPUT_JSON} ({len(domains):,} domínios únicos)")
    print(f"\n  Copie o blacklist.json para:")
    print(f"    ../extensao-phishing/assets/blacklist.json")
    print("=" * 60)


if __name__ == "__main__":
    main()
