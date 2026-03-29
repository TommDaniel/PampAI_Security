"""
Coletor de Whitelist de Dominios Legitimos
============================================
Baixa listas publicas de dominios populares/confiaveis e combina com
uma lista curada de dominios brasileiros para gerar uma whitelist
confiavel para a extensao anti-phishing.

Fontes globais:
  - Tranco Top List (research-grade, anti-manipulation)
  - Majestic Million (top domains by referring subnets)

Fontes BR curadas:
  - Bancos (autorizados pelo Banco Central)
  - Governo (.gov.br)
  - Telecomunicacoes
  - Universidades federais/estaduais
  - E-commerce e servicos populares

Saida:
  whitelist.csv   — auditoria (domain, source, category)
  whitelist.json  — array de dominios para a extensao

Uso:
  pip install requests pandas
  python coletar_whitelist.py [--top N]

Depois copie o whitelist.json para:
  ../extensao-phishing/assets/whitelist.json
"""

import argparse
import json
import os
import sys
import time
from io import StringIO
from urllib.parse import urlparse

import pandas as pd
import requests

OUTPUT_CSV = "whitelist.csv"
OUTPUT_JSON = "whitelist.json"
STATS_JSON = "whitelist_stats.json"

HEADERS = {
    "User-Agent": "TCC-Phishing-Research/1.0 (Academic Research; Whitelist Collection)"
}

# ============================================================
# Helpers
# ============================================================

def extract_domain(raw: str) -> str:
    """Extrai dominio limpo de uma string (URL ou dominio puro)."""
    raw = raw.strip().lower()
    if not raw:
        return ""
    try:
        if raw.startswith(("http://", "https://")):
            return urlparse(raw).hostname or ""
        # Remove porta se houver
        if ":" in raw:
            raw = raw.split(":")[0]
        # Remove path se houver
        if "/" in raw:
            raw = raw.split("/")[0]
        return raw
    except Exception:
        return ""


def is_valid_domain(domain: str) -> bool:
    """Valida formato basico de dominio."""
    if not domain or len(domain) < 3:
        return False
    if "." not in domain:
        return False
    # Rejeita IPs
    parts = domain.split(".")
    if all(p.isdigit() for p in parts):
        return False
    # Rejeita dominios com chars invalidos
    import re
    if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$', domain):
        return False
    return True


# ============================================================
# Fontes globais
# ============================================================

def collect_tranco(top_n: int = 10000) -> list[dict]:
    """
    Tranco List — ranking de dominios para pesquisa em seguranca.
    Resistente a manipulacao, atualizado diariamente.
    """
    print(f"  [Tranco] Baixando top {top_n:,} dominios...")
    try:
        # Pega o ID da lista mais recente
        r = requests.get("https://tranco-list.eu/top-1m-id", headers=HEADERS, timeout=30)
        if r.status_code != 200:
            print(f"    Erro ao obter ID: HTTP {r.status_code}")
            # Fallback: URL fixa da lista diaria
            download_url = "https://tranco-list.eu/top-1m.csv.zip"
        else:
            list_id = r.text.strip()
            print(f"    Lista ID: {list_id}")
            download_url = f"https://tranco-list.eu/download/{list_id}/1000000"

        # Baixa a lista (CSV simples: rank,domain)
        r = requests.get(download_url, headers=HEADERS, timeout=120)
        if r.status_code != 200:
            print(f"    HTTP {r.status_code}")
            return []

        # Se for zip, descompactar
        if download_url.endswith(".zip") or r.headers.get("content-type", "").startswith("application/zip"):
            import zipfile
            from io import BytesIO
            with zipfile.ZipFile(BytesIO(r.content)) as zf:
                csv_name = zf.namelist()[0]
                csv_data = zf.read(csv_name).decode("utf-8")
        else:
            csv_data = r.text

        result = []
        for line in csv_data.strip().split("\n")[:top_n]:
            parts = line.strip().split(",")
            if len(parts) >= 2:
                domain = extract_domain(parts[1])
                if is_valid_domain(domain):
                    result.append({
                        "domain": domain,
                        "source": "tranco",
                        "category": "global_popular",
                        "rank": int(parts[0]) if parts[0].isdigit() else 0
                    })

        print(f"    -> {len(result):,} dominios")
        return result
    except Exception as e:
        print(f"    Erro: {e}")
        return []


def collect_majestic(top_n: int = 10000) -> list[dict]:
    """Majestic Million — top dominios por subnets referenciadores."""
    print(f"  [Majestic] Baixando top {top_n:,} dominios...")
    try:
        r = requests.get(
            "https://downloads.majestic.com/majestic_million.csv",
            headers=HEADERS, timeout=120, stream=True
        )
        if r.status_code != 200:
            print(f"    HTTP {r.status_code}")
            return []

        lines = []
        for i, line in enumerate(r.iter_lines(decode_unicode=True)):
            lines.append(line)
            if i >= top_n + 1:  # +1 pro header
                break

        if len(lines) < 2:
            return []

        df = pd.read_csv(StringIO("\n".join(lines)), on_bad_lines="skip")
        domain_col = next((c for c in df.columns if "domain" in c.lower()), None)
        if not domain_col:
            print("    Coluna Domain nao encontrada")
            return []

        result = []
        for _, row in df.iterrows():
            domain = extract_domain(str(row[domain_col]))
            if is_valid_domain(domain):
                result.append({
                    "domain": domain,
                    "source": "majestic",
                    "category": "global_popular",
                    "rank": int(row.get("GlobalRank", 0)) if "GlobalRank" in df.columns else 0
                })

        print(f"    -> {len(result):,} dominios")
        return result
    except Exception as e:
        print(f"    Erro: {e}")
        return []


# ============================================================
# Dominios brasileiros curados
# ============================================================

def collect_br_curated() -> list[dict]:
    """
    Lista curada de dominios brasileiros confiaveis.
    Todos verificados manualmente como instituicoes legitimas.
    """
    print("  [BR Curado] Carregando dominios brasileiros...")

    domains = {
        # --- Bancos (autorizados pelo Banco Central) ---
        "bancos": [
            "bb.com.br", "itau.com.br", "itau.com", "bradesco.com.br",
            "santander.com.br", "caixa.gov.br", "banrisul.com.br",
            "sicredi.com.br", "sicoob.com.br", "inter.co",
            "bancointer.com.br", "c6bank.com.br", "nubank.com.br",
            "btgpactual.com", "safra.com.br", "original.com.br",
            "bancopan.com.br", "daycoval.com.br", "banese.com.br",
            "brb.com.br", "banestes.com.br", "bancodobrasil.com.br",
            "itauunibanco.com.br", "bradesconet.com.br",
            "santandernet.com.br", "caixaeconomica.com.br",
            "picpay.com", "stone.com.br", "pagseguro.com.br",
            "mercadopago.com.br", "iti.itau",
        ],
        # --- Governo federal ---
        "governo": [
            "gov.br", "planalto.gov.br", "receita.fazenda.gov.br",
            "esic.gov.br", "comprasnet.gov.br", "inss.gov.br",
            "dataprev.gov.br", "serpro.gov.br", "ibge.gov.br",
            "inep.gov.br", "capes.gov.br", "cnpq.gov.br",
            "anatel.gov.br", "anvisa.gov.br", "ans.gov.br",
            "anac.gov.br", "bcb.gov.br", "cvm.gov.br",
            "susep.gov.br", "detran.gov.br", "dpf.gov.br",
            "tse.jus.br", "stf.jus.br", "stj.jus.br",
            "trf1.jus.br", "tjsp.jus.br", "tjrj.jus.br",
            "senado.leg.br", "camara.leg.br",
        ],
        # --- Telecomunicacoes ---
        "telecom": [
            "vivo.com.br", "tim.com.br", "claro.com.br",
            "oi.com.br", "algar.com.br", "nextel.com.br",
            "sky.com.br", "net.com.br",
        ],
        # --- Universidades ---
        "universidades": [
            "usp.br", "unicamp.br", "ufrj.br", "ufmg.br",
            "ufrgs.br", "ufpr.br", "ufsc.br", "unb.br",
            "ufscar.br", "ufpe.br", "ufba.br", "ufce.br",
            "ufsm.br", "uel.br", "uem.br", "pucrs.br",
            "puc-rio.br", "mackenzie.br", "fgv.br",
            "insper.edu.br", "fiap.com.br",
        ],
        # --- E-commerce e servicos ---
        "ecommerce": [
            "mercadolivre.com.br", "americanas.com.br",
            "magazineluiza.com.br", "submarino.com.br",
            "casasbahia.com.br", "extra.com.br",
            "shopee.com.br", "amazon.com.br",
            "aliexpress.com", "shoptime.com.br",
            "pontofrio.com.br", "dafiti.com.br",
            "netshoes.com.br", "centauro.com.br",
            "kabum.com.br", "terabyteshop.com.br",
            "pichau.com.br",
        ],
        # --- Portais, midia e entretenimento ---
        "midia": [
            "globo.com", "g1.globo.com", "ge.globo.com",
            "uol.com.br", "folha.uol.com.br", "r7.com",
            "terra.com.br", "ig.com.br", "estadao.com.br",
            "band.uol.com.br", "sbt.com.br", "record.com.br",
            "infomoney.com.br", "valor.globo.com",
            "cnnbrasil.com.br",
        ],
        # --- Servicos e utilities ---
        "servicos": [
            "ifood.com.br", "rappi.com.br", "uber.com",
            "99app.com", "olx.com.br", "zapimoveis.com.br",
            "vivareal.com.br", "quintoandar.com.br",
            "decolar.com", "latamairlines.com", "azul.com.br",
            "gol.com.br", "correios.com.br", "buscacep.correios.com.br",
            "conectesus.saude.gov.br", "meuinss.gov.br",
        ],
    }

    result = []
    for category, domain_list in domains.items():
        for domain in domain_list:
            d = extract_domain(domain)
            if is_valid_domain(d):
                result.append({
                    "domain": d,
                    "source": "curated_br",
                    "category": category,
                    "rank": 0
                })

    print(f"    -> {len(result)} dominios em {len(domains)} categorias")
    return result


# ============================================================
# Dominios globais curados (grandes plataformas)
# ============================================================

def collect_global_curated() -> list[dict]:
    """Plataformas globais que devem estar sempre na whitelist."""
    print("  [Global Curado] Carregando plataformas globais...")

    domains = {
        "search_engines": [
            "google.com", "google.com.br", "bing.com", "yahoo.com",
            "duckduckgo.com", "baidu.com", "yandex.com",
        ],
        "social_media": [
            "facebook.com", "instagram.com", "twitter.com", "x.com",
            "linkedin.com", "reddit.com", "tiktok.com", "pinterest.com",
            "tumblr.com", "whatsapp.com", "telegram.org", "signal.org",
        ],
        "tech_platforms": [
            "github.com", "gitlab.com", "stackoverflow.com",
            "medium.com", "dev.to", "npmjs.com", "pypi.org",
            "docker.com", "hub.docker.com",
        ],
        "cloud_providers": [
            "microsoft.com", "azure.com", "live.com", "outlook.com",
            "office.com", "apple.com", "icloud.com",
            "amazon.com", "aws.amazon.com",
            "cloud.google.com", "firebase.google.com",
            "cloudflare.com", "digitalocean.com", "heroku.com",
            "vercel.com", "netlify.com",
        ],
        "entertainment": [
            "youtube.com", "netflix.com", "spotify.com",
            "twitch.tv", "steampowered.com", "epicgames.com",
            "ea.com", "blizzard.com", "riotgames.com",
            "playstation.com", "xbox.com", "nintendo.com",
        ],
        "ai_platforms": [
            "openai.com", "chatgpt.com", "claude.ai", "anthropic.com",
            "gemini.google.com", "copilot.microsoft.com",
            "huggingface.co", "kaggle.com",
        ],
        "email_providers": [
            "gmail.com", "outlook.com", "yahoo.com",
            "protonmail.com", "proton.me", "zoho.com",
        ],
        "ecommerce_global": [
            "ebay.com", "aliexpress.com", "etsy.com",
            "shopify.com", "paypal.com", "stripe.com",
        ],
        "reference": [
            "wikipedia.org", "wikimedia.org", "archive.org",
            "britannica.com",
        ],
    }

    result = []
    for category, domain_list in domains.items():
        for domain in domain_list:
            d = extract_domain(domain)
            if is_valid_domain(d):
                result.append({
                    "domain": d,
                    "source": "curated_global",
                    "category": category,
                    "rank": 0
                })

    print(f"    -> {len(result)} dominios")
    return result


# ============================================================
# Validacao cruzada
# ============================================================

def cross_validate_with_blacklist(
    df: pd.DataFrame, blacklist_path: str
) -> tuple[pd.DataFrame, int]:
    """
    Remove dominios que aparecem em blacklists conhecidas,
    MAS preserva dominios de fontes curadas (curated_br, curated_global)
    que sao verificados manualmente e confiaveis.

    Apenas dominios vindos de listas automaticas (tranco, majestic) sao removidos.
    """
    if not os.path.isfile(blacklist_path):
        print(f"  [Validacao] Blacklist nao encontrada: {blacklist_path}")
        return df, 0

    print(f"  [Validacao] Cruzando com blacklist...")
    try:
        with open(blacklist_path) as f:
            blacklist = set(json.load(f))

        in_blacklist = df["domain"].isin(blacklist)
        is_curated = df["source"].isin(["curated_br", "curated_global"])

        # So remove se esta na blacklist E nao e curado
        to_remove = in_blacklist & ~is_curated
        removed = df[to_remove]
        kept_despite_blacklist = df[in_blacklist & is_curated]

        if len(removed) > 0:
            print(f"    REMOVIDOS {len(removed)} dominios automaticos presentes na blacklist:")
            for d in sorted(removed["domain"].tolist())[:15]:
                print(f"      - {d}")
            if len(removed) > 15:
                print(f"      ... e mais {len(removed) - 15}")

        if len(kept_despite_blacklist) > 0:
            print(f"    MANTIDOS {len(kept_despite_blacklist)} dominios curados (apesar de estarem na blacklist):")
            for d in sorted(kept_despite_blacklist["domain"].tolist())[:10]:
                print(f"      - {d} (curado — confiavel)")

        return df[~to_remove], len(removed)
    except Exception as e:
        print(f"    Erro ao ler blacklist: {e}")
        return df, 0


# ============================================================
# Pipeline principal
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Coletor de whitelist de dominios legitimos")
    parser.add_argument("--top", type=int, default=10000,
                        help="Quantidade de dominios do Tranco/Majestic (default: 10000)")
    parser.add_argument("--skip-download", action="store_true",
                        help="Pula download das listas (usa apenas curados)")
    args = parser.parse_args()

    print("=" * 60)
    print("  COLETOR DE WHITELIST DE DOMINIOS LEGITIMOS")
    print("=" * 60)

    all_data = []

    # 1. Fontes curadas (sempre incluidas)
    all_data.extend(collect_global_curated())
    all_data.extend(collect_br_curated())

    # 2. Fontes remotas (se nao --skip-download)
    if not args.skip_download:
        all_data.extend(collect_tranco(top_n=args.top))
        time.sleep(1)
        all_data.extend(collect_majestic(top_n=args.top))
    else:
        print("  [Skip] Download de listas remotas pulado (--skip-download)")

    print(f"\n[PROCESSANDO]")

    # Criar DataFrame e deduplicar
    df = pd.DataFrame(all_data)
    total_raw = len(df)
    df = df[df["domain"].apply(is_valid_domain)]

    # Deduplicar mantendo a fonte com melhor rank
    df = df.sort_values("rank").drop_duplicates(subset=["domain"], keep="first")

    # Gerar variantes com www
    extra_rows = []
    for _, row in df.iterrows():
        d = row["domain"]
        if not d.startswith("www."):
            www_d = f"www.{d}"
            if www_d not in df["domain"].values:
                extra_rows.append({
                    "domain": www_d,
                    "source": row["source"],
                    "category": row["category"],
                    "rank": row["rank"]
                })

    if extra_rows:
        df = pd.concat([df, pd.DataFrame(extra_rows)], ignore_index=True)
        df = df.drop_duplicates(subset=["domain"], keep="first")

    print(f"  Total bruto: {total_raw:,}")
    print(f"  Apos deduplicacao + www: {len(df):,}")

    # 3. Validacao cruzada com blacklist
    blacklist_path = os.path.join(os.path.dirname(__file__), "..", "blacklist", "blacklist.json")
    df, num_removed = cross_validate_with_blacklist(df, blacklist_path)
    if num_removed:
        print(f"  Apos remover conflitos: {len(df):,}")

    # Stats
    print(f"\n  Por fonte:")
    for src, cnt in df["source"].value_counts().items():
        print(f"    {src}: {cnt:,}")
    print(f"\n  Por categoria:")
    for cat, cnt in df["category"].value_counts().items():
        print(f"    {cat}: {cnt:,}")

    # ---- Salvar CSV ----
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"\n  CSV salvo: {OUTPUT_CSV} ({len(df):,} entradas)")

    # ---- Salvar JSON (array de dominios) ----
    domains = sorted(df["domain"].unique().tolist())
    with open(OUTPUT_JSON, "w") as f:
        json.dump(domains, f, indent=2)
    print(f"  JSON salvo: {OUTPUT_JSON} ({len(domains):,} dominios)")

    # ---- Salvar stats ----
    stats = {
        "total_domains": len(domains),
        "sources": {src: int(cnt) for src, cnt in df["source"].value_counts().items()},
        "categories": {cat: int(cnt) for cat, cnt in df["category"].value_counts().items()},
        "blacklist_conflicts_removed": num_removed,
        "top_n_used": args.top,
    }
    with open(STATS_JSON, "w") as f:
        json.dump(stats, f, indent=2)

    print(f"\n  Copie o whitelist.json para:")
    print(f"    ../extensao-phishing/assets/whitelist.json")
    print("=" * 60)


if __name__ == "__main__":
    main()
