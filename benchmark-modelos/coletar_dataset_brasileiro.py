"""
Coletor de Dataset Brasileiro de Phishing
==========================================
Coleta URLs de phishing e legitimas brasileiras de multiplas fontes,
com foco na regiao Sul (PR, SC, RS).

Fontes de phishing:
  - PhishStats API (countrycode=BR, tld=br)
  - PhishStats CSV bulk (fallback)
  - OpenPhish feed
  - PhishTank CSV

Fontes legitimas:
  - Tranco List (top sites .br)
  - Majestic Million (TLD=br)
  - Curadoria manual da regiao Sul

Output: dataset_phishing_brasileiro.csv
"""

import requests
import pandas as pd
import time
import re
import sys
from io import StringIO

try:
    from datasets import load_dataset
    HF_AVAILABLE = True
except ImportError:
    HF_AVAILABLE = False

# ============================================================
# Configuracao
# ============================================================
PHISHING_TARGET = 5000
LEGIT_TARGET = 5000
OUTPUT_FILE = "dataset_phishing_brasileiro.csv"

HEADERS = {
    "User-Agent": "TCC-Phishing-Research/1.0 (Academic Research; Brazilian Phishing Dataset)"
}

# Keywords para identificar phishing direcionado ao Brasil
BR_PHISHING_KEYWORDS = [
    r"\.br[/\s$]", r"\.br$",
    "bradesco", "itau", "nubank", "banco do brasil", "bb.com",
    "caixa", "santander", "sicredi", "sicoob", "banrisul",
    r"correios", r"gov\.br", "receita", "detran", r"sus\.gov",
    "boleto", "pix", "cpf", "cnpj",
    "mercadolivre", "mercadopago", "magazineluiza", "magalu",
    r"americanas", r"casasbahia", r"shopee\.com\.br",
    r"vivo", r"claro", r"tim\.com\.br", r"oi\.com\.br",
    r"globo\.com", r"uol\.com\.br", r"terra\.com\.br",
    r"ifood", r"99app", r"uber\.com\.br",
    "serasa", "spc", "nota fiscal", "nfe",
]

BR_PATTERN = re.compile("|".join(BR_PHISHING_KEYWORDS), re.IGNORECASE)


# ============================================================
# 1. Coleta de Phishing
# ============================================================

def collect_phishstats_api(limit=3000):
    """Coleta URLs de phishing brasileiras via PhishStats API."""
    print("  [PhishStats API] Coletando phishing com countrycode=BR e tld=br...")
    urls = []
    page_size = 100

    # Busca por countrycode=BR
    for page in range(0, limit // page_size):
        try:
            resp = requests.get(
                f"https://phishstats.info:2096/api/phishing",
                params={
                    "_where": "(countrycode,eq,BR)",
                    "_sort": "-date",
                    "_size": page_size,
                    "_p": page,
                },
                headers=HEADERS,
                timeout=30,
            )
            if resp.status_code != 200:
                break
            data = resp.json()
            if not data:
                break
            for item in data:
                urls.append({
                    "url": item.get("url", ""),
                    "label": 1,
                    "source": "phishstats_api_BR",
                    "region": "brasil",
                })
            time.sleep(0.5)  # respeitar rate limit (20 req/min)
        except Exception as e:
            print(f"    Erro na pagina {page}: {e}")
            break

    # Busca por tld=br (pode trazer URLs diferentes)
    for page in range(0, limit // page_size):
        try:
            resp = requests.get(
                f"https://phishstats.info:2096/api/phishing",
                params={
                    "_where": "(tld,eq,br)",
                    "_sort": "-date",
                    "_size": page_size,
                    "_p": page,
                },
                headers=HEADERS,
                timeout=30,
            )
            if resp.status_code != 200:
                break
            data = resp.json()
            if not data:
                break
            for item in data:
                urls.append({
                    "url": item.get("url", ""),
                    "label": 1,
                    "source": "phishstats_api_tld_br",
                    "region": "brasil",
                })
            time.sleep(0.5)
        except Exception as e:
            print(f"    Erro na pagina {page}: {e}")
            break

    print(f"    -> {len(urls)} URLs coletadas")
    return urls


def collect_phishstats_csv():
    """Fallback: baixa CSV completo do PhishStats e filtra .br."""
    print("  [PhishStats CSV] Baixando CSV bulk e filtrando .br...")
    urls = []
    try:
        resp = requests.get(
            "https://phishstats.info/phish_score.csv",
            headers=HEADERS,
            timeout=120,
            stream=True,
        )
        if resp.status_code != 200:
            print(f"    HTTP {resp.status_code}")
            return urls

        # Ler em chunks para nao estourar memoria
        lines = []
        for i, line in enumerate(resp.iter_lines(decode_unicode=True)):
            if line and not line.startswith("#"):
                lines.append(line)
            if i > 500_000:  # limitar leitura
                break

        if len(lines) < 2:
            print("    CSV vazio ou inacessivel")
            return urls

        csv_text = "\n".join(lines)
        df = pd.read_csv(StringIO(csv_text), on_bad_lines="skip")

        # Encontrar a coluna de URL
        url_col = None
        for col in df.columns:
            if "url" in col.lower():
                url_col = col
                break
        if url_col is None:
            print("    Coluna de URL nao encontrada")
            return urls

        # Filtrar brasileiras
        mask = df[url_col].astype(str).str.contains(BR_PATTERN, na=False)
        df_br = df[mask]

        for _, row in df_br.iterrows():
            urls.append({
                "url": str(row[url_col]),
                "label": 1,
                "source": "phishstats_csv",
                "region": "brasil",
            })

        print(f"    -> {len(urls)} URLs brasileiras filtradas do CSV")
    except Exception as e:
        print(f"    Erro: {e}")
    return urls


def collect_openphish():
    """Coleta do feed OpenPhish e filtra URLs brasileiras."""
    print("  [OpenPhish] Baixando feed...")
    urls = []
    try:
        resp = requests.get(
            "https://openphish.com/feed.txt",
            headers=HEADERS,
            timeout=30,
        )
        if resp.status_code != 200:
            print(f"    HTTP {resp.status_code}")
            return urls

        all_urls = resp.text.strip().split("\n")
        for u in all_urls:
            u = u.strip()
            if BR_PATTERN.search(u):
                urls.append({
                    "url": u,
                    "label": 1,
                    "source": "openphish",
                    "region": "brasil",
                })

        print(f"    -> {len(urls)} URLs brasileiras de {len(all_urls)} total")
    except Exception as e:
        print(f"    Erro: {e}")
    return urls


def collect_phishtank():
    """Coleta do PhishTank CSV e filtra URLs brasileiras."""
    print("  [PhishTank] Baixando CSV...")
    urls = []
    try:
        resp = requests.get(
            "https://data.phishtank.com/data/online-valid.csv",
            headers=HEADERS,
            timeout=120,
        )
        if resp.status_code != 200:
            print(f"    HTTP {resp.status_code} (PhishTank pode bloquear requests automaticos)")
            return urls

        df = pd.read_csv(StringIO(resp.text), usecols=["url", "target"], on_bad_lines="skip")

        # Filtrar por URL .br ou target brasileiro
        br_url_mask = df["url"].astype(str).str.contains(BR_PATTERN, na=False)
        br_target_mask = df["target"].astype(str).str.contains(
            r"brazil|brasil|bradesco|itau|nubank|caixa|banco|bb\.com|santander|sicredi|banrisul",
            case=False, na=False,
        )
        df_br = df[br_url_mask | br_target_mask]

        for _, row in df_br.iterrows():
            urls.append({
                "url": str(row["url"]),
                "label": 1,
                "source": "phishtank",
                "region": "brasil",
            })

        print(f"    -> {len(urls)} URLs brasileiras encontradas")
    except Exception as e:
        print(f"    Erro: {e}")
    return urls


# ============================================================
# 2. Coleta de URLs Legitimas
# ============================================================

def collect_tranco_br(limit=3000):
    """Coleta dominios .br do Tranco List."""
    print("  [Tranco] Coletando dominios .br do ranking...")
    urls = []
    try:
        from tranco import Tranco
        t = Tranco(cache=True, cache_dir=".tranco_cache")
        latest = t.list()
        all_domains = latest.top(1_000_000)

        br_domains = [d for d in all_domains if d.endswith(".br")][:limit]

        for domain in br_domains:
            urls.append({
                "url": f"https://{domain}",
                "label": 0,
                "source": "tranco",
                "region": "brasil",
            })

        print(f"    -> {len(urls)} dominios .br encontrados")
    except ImportError:
        print("    tranco nao instalado (pip install tranco). Pulando...")
    except Exception as e:
        print(f"    Erro: {e}")
    return urls


def collect_majestic_br(limit=3000):
    """Coleta dominios .br do Majestic Million."""
    print("  [Majestic Million] Baixando e filtrando TLD=br...")
    urls = []
    try:
        resp = requests.get(
            "https://downloads.majestic.com/majestic_million.csv",
            headers=HEADERS,
            timeout=120,
        )
        if resp.status_code != 200:
            print(f"    HTTP {resp.status_code}")
            return urls

        df = pd.read_csv(StringIO(resp.text))
        df_br = df[df["TLD"] == "br"].head(limit)

        for _, row in df_br.iterrows():
            domain = row["Domain"]
            urls.append({
                "url": f"https://{domain}",
                "label": 0,
                "source": "majestic",
                "region": "brasil",
            })

        print(f"    -> {len(urls)} dominios .br encontrados")
    except Exception as e:
        print(f"    Erro: {e}")
    return urls


def get_south_brazil_urls():
    """URLs legitimas curadas da regiao Sul do Brasil (PR, SC, RS)."""
    print("  [Curadoria Sul] Adicionando URLs da regiao Sul...")

    # Dominios organizados por categoria
    domains = {
        # --- PARANA ---
        "governo_pr": [
            "www.parana.pr.gov.br",
            "www.curitiba.pr.gov.br",
            "www.londrina.pr.gov.br",
            "www.maringa.pr.gov.br",
            "www.cascavel.pr.gov.br",
            "www.pontagrossa.pr.gov.br",
            "www.fozdoiguacu.pr.gov.br",
            "www.saojosedospinhais.pr.gov.br",
            "www.colombo.pr.gov.br",
            "www.guarapuava.pr.gov.br",
            "www.detran.pr.gov.br",
            "www.educacao.pr.gov.br",
            "www.saude.pr.gov.br",
            "www.fazenda.pr.gov.br",
            "www.seguranca.pr.gov.br",
            "www.alep.pr.gov.br",
            "www.tjpr.jus.br",
            "www.mppr.mp.br",
            "www.tce.pr.gov.br",
            "www.tre-pr.jus.br",
        ],
        "universidades_pr": [
            "www.ufpr.br",
            "www.utfpr.edu.br",
            "www.uepg.br",
            "www.uel.br",
            "www.uem.br",
            "www.unioeste.br",
            "www.unicentro.br",
            "www.uenp.edu.br",
            "www.pucpr.br",
            "www.up.edu.br",
            "www.uninter.com",
            "www.fae.edu",
        ],
        "empresas_pr": [
            "www.copel.com",
            "www.sanepar.com.br",
            "www.portodesparanagua.pr.gov.br",
            "www.gazetadopovo.com.br",
            "www.bandab.com.br",
            "www.condor.com.br",
            "www.muffatosupermercados.com.br",
            "www.boticario.com.br",
            "www.positivo.com.br",
            "www.ebanx.com",
            "www.madeiramadeira.com.br",
            "www.brf.com",
        ],

        # --- SANTA CATARINA ---
        "governo_sc": [
            "www.sc.gov.br",
            "www.florianopolis.sc.gov.br",
            "www.joinville.sc.gov.br",
            "www.blumenau.sc.gov.br",
            "www.chapeco.sc.gov.br",
            "www.itajai.sc.gov.br",
            "www.criciuma.sc.gov.br",
            "www.balneariocamboriu.sc.gov.br",
            "www.jaragua.sc.gov.br",
            "www.lages.sc.gov.br",
            "www.detran.sc.gov.br",
            "www.sed.sc.gov.br",
            "www.saude.sc.gov.br",
            "www.alesc.sc.gov.br",
            "www.tjsc.jus.br",
            "www.mpsc.mp.br",
            "www.tce.sc.gov.br",
            "www.tre-sc.jus.br",
        ],
        "universidades_sc": [
            "www.ufsc.br",
            "www.udesc.br",
            "www.unochapeco.edu.br",
            "www.furb.br",
            "www.univali.br",
            "www.unisul.br",
            "www.unesc.net",
            "www.unoesc.edu.br",
            "www.ifsc.edu.br",
        ],
        "empresas_sc": [
            "www.weg.net",
            "www.celesc.com.br",
            "www.nsctotal.com.br",
            "www.clicrbs.com.br",
            "www.angeloni.com.br",
            "www.havan.com.br",
            "www.malwee.com.br",
            "www.portobello.com.br",
            "www.tigre.com.br",
            "www.tupy.com.br",
            "www.totvs.com",
        ],

        # --- RIO GRANDE DO SUL ---
        "governo_rs": [
            "www.rs.gov.br",
            "www.portoalegre.rs.gov.br",
            "www.caxiasdosul.rs.gov.br",
            "www.pelotas.rs.gov.br",
            "www.canoas.rs.gov.br",
            "www.santamaria.rs.gov.br",
            "www.gravatai.rs.gov.br",
            "www.novohamburgo.rs.gov.br",
            "www.viamao.rs.gov.br",
            "www.poa.ifrs.edu.br",
            "www.detran.rs.gov.br",
            "www.educacao.rs.gov.br",
            "www.saude.rs.gov.br",
            "www.sefaz.rs.gov.br",
            "www.al.rs.gov.br",
            "www.tjrs.jus.br",
            "www.mprs.mp.br",
            "www.tce.rs.gov.br",
            "www.tre-rs.jus.br",
        ],
        "universidades_rs": [
            "www.ufrgs.br",
            "www.ufsm.br",
            "www.ufpel.edu.br",
            "www.furg.br",
            "www.unipampa.edu.br",
            "www.uffs.edu.br",
            "www.pucrs.br",
            "www.unisinos.br",
            "www.feevale.br",
            "www.ucs.br",
            "www.ulbra.br",
            "www.ifrs.edu.br",
        ],
        "empresas_rs": [
            "www.banrisul.com.br",
            "www.gerdau.com",
            "www.tramontina.com.br",
            "www.randon.com.br",
            "www.marcopolo.com.br",
            "www.renner.com.br",
            "www.zerohora.com.br",
            "www.correiodopovo.com.br",
            "www.panvel.com",
            "www.zaffari.com.br",
            "www.colombo.com.br",
            "www.ceee.com.br",
            "www.corsan.com.br",
        ],

        # --- COOPERATIVAS E FINANCEIRAS REGIONAIS ---
        "financeiro_sul": [
            "www.sicredi.com.br",
            "www.sicoob.com.br",
            "www.cresol.com.br",
            "www.viacredi.coop.br",
            "www.unicred.com.br",
            "www.ailos.coop.br",
        ],

        # --- SERVICOS E SAUDE SUL ---
        "saude_sul": [
            "www.hospitaldeclinicas.ufpr.br",
            "www.hcpa.edu.br",
            "www.hu.ufsc.br",
            "www.unimed.coop.br",
            "www.unimedcuritiba.com.br",
            "www.unimedpoa.com.br",
        ],
    }

    # Paths reais para gerar variacoes
    paths = [
        "",
        "/login",
        "/contato",
        "/servicos",
        "/sobre",
        "/consulta",
        "/2a-via",
        "/fale-conosco",
        "/ouvidoria",
        "/portal",
        "/noticias",
        "/transparencia",
        "/licitacoes",
        "/concursos",
        "/aluno",
        "/academico",
        "/vestibular",
    ]

    urls = []
    for category, domain_list in domains.items():
        for domain in domain_list:
            # Determinar estado
            if "_pr" in category or any(s in domain for s in [".pr.", "curitib", "londrin", "maring"]):
                region = "sul_PR"
            elif "_sc" in category or any(s in domain for s in [".sc.", "florianopolis", "joinvill", "blumenau"]):
                region = "sul_SC"
            elif "_rs" in category or any(s in domain for s in [".rs.", "portoalegre", "caxias", "pelota"]):
                region = "sul_RS"
            else:
                region = "sul"

            # Gerar variações com diferentes paths
            n_paths = min(5, len(paths))  # 5 variações por dominio
            for path in paths[:n_paths]:
                full_url = f"https://{domain}{path}"
                urls.append({
                    "url": full_url,
                    "label": 0,
                    "source": f"curadoria_{category}",
                    "region": region,
                })

    print(f"    -> {len(urls)} URLs da regiao Sul geradas")
    return urls


def get_national_legit_urls():
    """URLs legitimas nacionais (bancos, governo federal, grandes portais)."""
    print("  [Curadoria Nacional] Adicionando URLs nacionais...")

    domains = [
        # Bancos
        "www.bb.com.br", "www.itau.com.br", "www.bradesco.com.br",
        "www.nubank.com.br", "www.caixa.gov.br", "www.santander.com.br",
        "www.bancointer.com.br", "www.c6bank.com.br", "www.original.com.br",
        "www.safra.com.br", "www.btgpactual.com",
        # Governo federal
        "www.gov.br", "www.receita.fazenda.gov.br", "www.inss.gov.br",
        "www.anatel.gov.br", "www.aneel.gov.br", "www.ans.gov.br",
        "www.anvisa.gov.br", "www.ibge.gov.br", "www.bcb.gov.br",
        "www.tse.jus.br", "www.stf.jus.br", "www.stj.jus.br",
        "www.senado.leg.br", "www.camara.leg.br",
        "www.dataprev.gov.br", "www.serpro.gov.br",
        # E-commerce
        "www.mercadolivre.com.br", "www.magazineluiza.com.br",
        "www.americanas.com.br", "www.casasbahia.com.br",
        "www.amazon.com.br", "www.shopee.com.br",
        "www.submarino.com.br", "www.pontofrio.com.br",
        "www.kabum.com.br", "www.pichau.com.br",
        # Servicos
        "www.correios.com.br", "www.ifood.com.br",
        "www.uber.com", "www.99app.com",
        "www.rappi.com.br", "www.sympla.com.br",
        # Telecom
        "www.vivo.com.br", "www.claro.com.br",
        "www.tim.com.br", "www.oi.com.br",
        # Midia
        "www.globo.com", "www.uol.com.br", "www.terra.com.br",
        "www.folha.uol.com.br", "www.estadao.com.br",
        "www.r7.com", "www.ig.com.br",
        # Financeiro
        "www.serasa.com.br", "www.boavistaservicos.com.br",
        "www.b3.com.br", "www.xpi.com.br",
        # Tech
        "www.locaweb.com.br", "www.hostgator.com.br",
    ]

    paths = ["", "/login", "/contato", "/ajuda", "/servicos"]
    urls = []
    for domain in domains:
        for path in paths[:3]:
            urls.append({
                "url": f"https://{domain}{path}",
                "label": 0,
                "source": "curadoria_nacional",
                "region": "brasil",
            })

    print(f"    -> {len(urls)} URLs nacionais geradas")
    return urls


# ============================================================
# 3. Dataset HuggingFace (kmack/Phishing_urls — 708k URLs)
# ============================================================

def collect_huggingface_dataset():
    """Carrega o dataset kmack/Phishing_urls do HuggingFace (708k URLs globais)."""
    if not HF_AVAILABLE:
        print("  [HuggingFace] 'datasets' não instalado. Rode: pip install datasets")
        return []

    print("  [HuggingFace] Carregando kmack/Phishing_urls...")
    try:
        dataset = load_dataset("kmack/Phishing_urls")
        dfs = []
        for split in ["train", "test", "valid"]:
            if split in dataset:
                dfs.append(dataset[split].to_pandas())

        df_hf = pd.concat(dfs, ignore_index=True)

        # Coluna de URL no dataset é 'text'
        urls = []
        for _, row in df_hf.iterrows():
            urls.append({
                "url":    str(row["text"]),
                "label":  int(row["label"]),
                "source": "kmack_phishing_urls",
                "region": "global",
            })

        n_phish = sum(1 for u in urls if u["label"] == 1)
        n_legit = sum(1 for u in urls if u["label"] == 0)
        print(f"    -> {len(urls):,} URLs carregadas (phishing: {n_phish:,} | legítimo: {n_legit:,})")
        return urls
    except Exception as e:
        print(f"    Erro ao carregar HuggingFace dataset: {e}")
        return []


# ============================================================
# 4. Pipeline principal
# ============================================================

def main():
    print("=" * 70)
    print("  COLETOR DE DATASET BRASILEIRO DE PHISHING")
    print("  Foco: URLs brasileiras com enfase na regiao Sul (PR, SC, RS)")
    print("=" * 70)

    all_data = []

    # --- Base global (HuggingFace) ---
    print("\n[FASE 0] Carregando base global kmack/Phishing_urls (HuggingFace)...")
    print("-" * 50)
    hf_data = collect_huggingface_dataset()
    all_data.extend(hf_data)
    print(f"  Base global: {len(hf_data):,} URLs adicionadas\n")

    # --- Phishing ---
    print("\n[FASE 1] Coletando URLs de PHISHING brasileiras...")
    print("-" * 50)

    sources_phishing = [
        ("PhishStats API", collect_phishstats_api),
        ("OpenPhish", collect_openphish),
        ("PhishTank", collect_phishtank),
    ]

    for name, func in sources_phishing:
        try:
            result = func()
            all_data.extend(result)
            print(f"    Subtotal phishing: {len([d for d in all_data if d['label'] == 1])}")
        except Exception as e:
            print(f"    [{name}] FALHOU: {e}")

    # Sempre tentar o CSV bulk do PhishStats para maximizar phishing BR
    n_phishing = len([d for d in all_data if d["label"] == 1])
    print(f"\n  Total phishing ate agora: {n_phishing}. Tentando PhishStats CSV bulk...")
    try:
        result = collect_phishstats_csv()
        all_data.extend(result)
    except Exception as e:
        print(f"    PhishStats CSV FALHOU: {e}")

    # --- Legitimas ---
    print(f"\n[FASE 2] Coletando URLs LEGITIMAS brasileiras...")
    print("-" * 50)

    # Curadoria manual (sempre funciona, sem dependencia de rede)
    all_data.extend(get_south_brazil_urls())
    all_data.extend(get_national_legit_urls())

    # Fontes online
    sources_legit = [
        ("Tranco", lambda: collect_tranco_br(2000)),
        ("Majestic", lambda: collect_majestic_br(2000)),
    ]

    for name, func in sources_legit:
        try:
            result = func()
            all_data.extend(result)
            print(f"    Subtotal legitimas: {len([d for d in all_data if d['label'] == 0])}")
        except Exception as e:
            print(f"    [{name}] FALHOU: {e}")

    # --- Montar DataFrame ---
    print(f"\n[FASE 3] Processando dataset...")
    print("-" * 50)

    df = pd.DataFrame(all_data)

    # Remover URLs vazias
    df = df[df["url"].str.strip().astype(bool)]

    # Normalizar URLs (lowercase do dominio para dedup)
    df["url_normalized"] = df["url"].str.strip().str.lower()
    df = df.drop_duplicates(subset=["url_normalized"])
    df = df.drop(columns=["url_normalized"])

    print(f"  Total apos deduplicacao: {len(df)}")

    # Contagens
    n_phishing = (df["label"] == 1).sum()
    n_legit = (df["label"] == 0).sum()
    print(f"  Phishing: {n_phishing} | Legitimo: {n_legit}")

    # Balancear: undersample da classe maior para igualar a menor
    if min(n_phishing, n_legit) > 0:
        target = min(n_phishing, n_legit)
        df_phish = df[df["label"] == 1].sample(n=target, random_state=42)
        df_legit = df[df["label"] == 0].sample(n=target, random_state=42)
        df = pd.concat([df_phish, df_legit], ignore_index=True)
        print(f"  Balanceamento: {target} phishing + {target} legitimas = {len(df)} total")

    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Exportar
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"\n  Dataset salvo em: {OUTPUT_FILE}")

    # --- Relatorio ---
    print("\n" + "=" * 70)
    print("  RELATORIO FINAL")
    print("=" * 70)
    print(f"\n  Total de URLs: {len(df)}")
    print(f"\n  Distribuicao por label:")
    for label, count in df["label"].value_counts().items():
        tipo = "Phishing" if label == 1 else "Legitimo"
        print(f"    {tipo}: {count} ({count/len(df):.1%})")

    print(f"\n  Distribuicao por fonte:")
    for source, count in df["source"].value_counts().items():
        print(f"    {source}: {count}")

    print(f"\n  Distribuicao por regiao:")
    for region, count in df["region"].value_counts().items():
        print(f"    {region}: {count}")

    # URLs da regiao Sul
    sul_mask = df["region"].str.startswith("sul")
    n_sul = sul_mask.sum()
    print(f"\n  URLs da Regiao Sul: {n_sul} ({n_sul/len(df):.1%})")
    if n_sul > 0:
        for region in sorted(df[sul_mask]["region"].unique()):
            count = (df["region"] == region).sum()
            print(f"    {region}: {count}")

    print(f"\n  Arquivo: {OUTPUT_FILE}")
    print("=" * 70)

    return df


if __name__ == "__main__":
    df = main()
