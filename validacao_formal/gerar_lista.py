"""
gerar_lista.py
==============

Gera ``lista_validacao.csv`` a partir das fontes consolidadas do projeto:
  - ``whitelist/whitelist.csv`` (Tranco + Majestic + curadoria global/BR)
  - ``blacklist/blacklist.json`` (PhishTank + OpenPhish + URLhaus + PhishStats
    + Phishing.Database, ~774 mil URLs)

A lista é determinística (random.seed fixo) para reprodutibilidade.

Composição alvo: ~2000 URLs, balanceadas em legítimas e phishing.

Uso:
  python gerar_lista.py [--total 2000] [--output lista_validacao.csv]
"""

import argparse
import csv
import json
import random
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WHITELIST_CSV = REPO_ROOT / "whitelist" / "whitelist.csv"
BLACKLIST_JSON = REPO_ROOT / "blacklist" / "blacklist.json"

SEED = 42

# ----------------------------------------------------------------------
# Marcas-alvo para amostragem prioritária da blacklist (phishings que
# tentam imitar essas marcas têm valor científico maior).
# ----------------------------------------------------------------------
MARCAS_GLOBAIS = [
    "paypal", "google", "amazon", "microsoft", "apple", "netflix",
    "facebook", "instagram", "whatsapp", "linkedin", "twitter", "spotify",
    "outlook", "office365", "icloud", "dropbox", "github", "ebay", "chase",
    "wellsfargo", "bankofamerica", "citi",
]

MARCAS_BR = [
    "bradesco", "itau", "caixa", "nubank", "santander", "bancobrasil",
    "bb.com", "mercadolivre", "magalu", "americanas", "correios",
    "gov.br", "receita", "detran", "submarino", "casasbahia", "shopee",
]

LEGIT_CURADAS_BR = [
    ("https://www.bb.com.br", "banco"),
    ("https://www.itau.com.br", "banco"),
    ("https://www.caixa.gov.br", "banco"),
    ("https://www.bradesco.com.br", "banco"),
    ("https://www.nubank.com.br", "banco"),
    ("https://www.santander.com.br", "banco"),
    ("https://www.bancointer.com.br", "banco"),
    ("https://banco.bradesco", "banco"),
    ("https://www.gov.br", "governo"),
    ("https://www.receita.fazenda.gov.br", "governo"),
    ("https://www.tse.jus.br", "governo"),
    ("https://www.stf.jus.br", "governo"),
    ("https://www.camara.leg.br", "governo"),
    ("https://www.senado.leg.br", "governo"),
    ("https://www.tjsp.jus.br", "governo"),
    ("https://www.detran.sp.gov.br", "governo"),
    ("https://www.correios.com.br", "governo"),
    ("https://www.bcb.gov.br", "governo"),
    ("https://www.poupatempo.sp.gov.br", "governo"),
    ("https://www.cnh.detran.sp.gov.br", "governo"),
    ("https://www.unipampa.edu.br", "universidade-do-autor"),
    ("https://guri.unipampa.edu.br", "universidade-do-autor"),
    ("https://www.usp.br", "universidade"),
    ("https://www.unicamp.br", "universidade"),
    ("https://www.ufrgs.br", "universidade"),
    ("https://www.ufsc.br", "universidade"),
    ("https://www.pucrs.br", "universidade"),
    ("https://www.ufsm.br", "universidade"),
    ("https://www.ufpel.edu.br", "universidade"),
    ("https://www.fgv.br", "universidade"),
    ("https://www.unesp.br", "universidade"),
    ("https://www.serasa.com.br", "servico"),
    ("https://www.spcbrasil.org.br", "servico"),
    ("https://www.einstein.br", "saude"),
    ("https://www.albertsabin.com.br", "saude"),
    ("https://www.fleury.com.br", "saude"),
    ("https://www.hapvida.com.br", "saude"),
    ("https://www.amil.com.br", "saude"),
    ("https://www.unimed.coop.br", "saude"),
    ("https://www.tudoazul.com", "viagem"),
    ("https://www.smiles.com.br", "viagem"),
    ("https://www.latam.com", "viagem"),
    ("https://www.azul.com.br", "viagem"),
    ("https://www.gol.com.br", "viagem"),
    ("https://www.airbnb.com.br", "viagem"),
    ("https://www.decolar.com", "viagem"),
]

PHISHING_SINTETICAS = [
    # IP-based
    ("http://192.168.1.100/login/bancodobrasil", "ip-based"),
    ("http://45.33.32.156/secure/itau-login.php", "ip-based"),
    ("http://185.234.219.45/caixa/atualizar-dados", "ip-based"),
    ("http://103.45.67.89/netflix/verify-account", "ip-based"),
    ("http://91.134.200.33/paypal-confirm/index.html", "ip-based"),
    # Typosquatting / homoglifos
    ("http://www.g00gle-login.com/accounts/verify", "typosquatting"),
    ("http://www.faceb00k-security.com/login", "typosquatting"),
    ("http://www.amaz0n-verify.com/account/confirm", "typosquatting"),
    ("http://www.paypa1-secure.com/update-info", "typosquatting"),
    ("http://www.netfl1x-account.com/billing/update", "typosquatting"),
    # Subdomínios suspeitos
    ("http://login.bradesco.com.secure-update.xyz/verify", "subdominio"),
    ("http://itau.com.br.account-verify.tk/login", "subdominio"),
    ("http://bb.com.br.secure-banking.ml/atualizar", "subdominio"),
    ("http://santander.com.br.verify-account.ga/login", "subdominio"),
    ("http://nubank.com.br.update-security.cf/dados", "subdominio"),
    # Domínios longos / verborrágicos
    ("http://secure-banking-update-your-account-now-bradesco.com/login", "dominio-longo"),
    ("http://verificacao-conta-bancaria-urgente-caixa.com.br.xyz.com/form", "dominio-longo"),
    ("http://atualizacao-cadastro-obrigatoria-bb.net/verify", "dominio-longo"),
    ("http://confirmar-identidade-itau-seguranca.org/dados", "dominio-longo"),
    ("http://revalidar-token-seguranca-nubank-app.com/auth", "dominio-longo"),
    # Imitando marcas globais
    ("http://microsoft-365-security-alert.com/verify", "marca-global"),
    ("http://apple-id-suspended-verify.com/login", "marca-global"),
    ("http://google-account-recovery-alert.com/signin", "marca-global"),
    ("http://instagram-verify-badge.com/confirm", "marca-global"),
    ("http://linkedin-profile-security.com/update", "marca-global"),
    # Imitando marcas BR
    ("http://www.banco-do-brasil-seguro.com/login", "marca-br"),
    ("http://caixa-gov-br.com/atualizar-cadastro", "marca-br"),
    ("http://receita-federal-restituicao.com/consultar", "marca-br"),
    ("http://correios-rastreamento-encomenda.com/tracking", "marca-br"),
    ("http://detran-consulta-multas.net/verificar", "marca-br"),
    # TLDs suspeitos
    ("http://login-bancodobrasil.top/verify", "tld-suspeito"),
    ("http://itau-internet-banking.xyz/secure", "tld-suspeito"),
    ("http://caixa-economica-federal.top/atualizar", "tld-suspeito"),
    ("http://bradesco-prime.xyz/conta/verificar", "tld-suspeito"),
    ("http://banco-inter-app.top/login/seguro", "tld-suspeito"),
    ("https://secure-login-bradesco.tk/app/verify", "tld-suspeito"),
    ("https://www.itau-seguranca-digital.xyz/login", "tld-suspeito"),
    ("https://caixa-atualizacao-obrigatoria.ml/form", "tld-suspeito"),
    ("https://santander-verificacao-conta.ga/dados", "tld-suspeito"),
    ("https://nubank-confirmar-identidade.cf/auth", "tld-suspeito"),
    # Outros padrões
    ("http://suporte-mercadolivre.com/verificar-conta", "marca-br"),
    ("http://alert-netflix-payment.com/update-billing", "marca-global"),
    ("http://spotify-premium-free.com/claim", "marca-global"),
]


def carregar_whitelist() -> list[dict]:
    if not WHITELIST_CSV.exists():
        raise FileNotFoundError(f"whitelist.csv não encontrada em {WHITELIST_CSV}")
    rows = []
    with WHITELIST_CSV.open("r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows.append(row)
    return rows


def carregar_blacklist() -> list[str]:
    if not BLACKLIST_JSON.exists():
        raise FileNotFoundError(f"blacklist.json não encontrada em {BLACKLIST_JSON}")
    with BLACKLIST_JSON.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def amostra_legitimas(whitelist_rows: list[dict], n: int, rng: random.Random) -> list[dict]:
    """Top da whitelist: prefere rank baixo (mais acessadas), filtra duplicatas."""
    # Ordena por rank ascendente quando disponível
    def _rank(r):
        try:
            return int(r.get("rank", 999_999))
        except (TypeError, ValueError):
            return 999_999

    rows = sorted(whitelist_rows, key=_rank)
    seen = set()
    out = []
    for row in rows:
        domain = row["domain"].strip().lower()
        if domain in seen or not domain or "." not in domain or len(domain) > 80:
            continue
        seen.add(domain)
        out.append({
            "url": f"https://{domain}",
            "label": "legitimate",
            "fonte": row.get("source", "whitelist"),
            "nota": row.get("category", ""),
        })
        if len(out) >= n:
            break
    rng.shuffle(out)
    return out


def amostra_phishing_marcas(blacklist: list[str], marcas: list[str],
                             n_por_marca: int, rng: random.Random,
                             max_total: int) -> list[dict]:
    """Para cada marca, pega n_por_marca URLs de phishing que mencionam a marca."""
    selecionadas = []
    seen = set()
    for marca in marcas:
        candidatos = [
            d for d in blacklist
            if marca in d.lower() and 8 <= len(d) <= 80 and "." in d and not d.startswith("%")
        ]
        rng.shuffle(candidatos)
        adicionados = 0
        for d in candidatos:
            if d in seen:
                continue
            seen.add(d)
            url = f"http://{d}" if not d.startswith("http") else d
            selecionadas.append({
                "url": url,
                "label": "phishing",
                "fonte": "blacklist-real",
                "nota": f"imita-{marca}",
            })
            adicionados += 1
            if adicionados >= n_por_marca or len(selecionadas) >= max_total:
                break
        if len(selecionadas) >= max_total:
            break
    return selecionadas


def amostra_phishing_geral(blacklist: list[str], n: int, rng: random.Random,
                            evitar: set) -> list[dict]:
    """Amostra random da blacklist sem viés de marca."""
    candidatos = [
        d for d in blacklist
        if 8 <= len(d) <= 80 and "." in d and not d.startswith("%") and d not in evitar
    ]
    pegos = rng.sample(candidatos, min(n, len(candidatos)))
    return [
        {
            "url": f"http://{d}",
            "label": "phishing",
            "fonte": "blacklist-real",
            "nota": "amostra-geral",
        }
        for d in pegos
    ]


def main():
    parser = argparse.ArgumentParser(description="Gera lista_validacao.csv a partir das fontes do projeto.")
    parser.add_argument("--total", type=int, default=2000,
                        help="Total alvo de URLs (~50/50 legit/phishing). Default 2000.")
    parser.add_argument("--output", default=str(Path(__file__).parent / "lista_validacao.csv"),
                        help="Arquivo CSV de saída.")
    args = parser.parse_args()

    rng = random.Random(SEED)
    n_legit_alvo = args.total // 2
    n_phish_alvo = args.total - n_legit_alvo

    # ----- Legítimas -----
    print(f"Carregando whitelist.csv...")
    whitelist_rows = carregar_whitelist()
    print(f"  {len(whitelist_rows):,} entradas na whitelist.")

    # Reservar slots para curadoria BR (entram com prioridade)
    n_curadas = len(LEGIT_CURADAS_BR)
    n_top = n_legit_alvo - n_curadas

    legit_top = amostra_legitimas(whitelist_rows, n_top, rng)
    legit_curadas = [
        {"url": url, "label": "legitimate", "fonte": "curadoria-br", "nota": nota}
        for url, nota in LEGIT_CURADAS_BR
    ]
    legit = legit_curadas + legit_top
    print(f"  Selecionadas {len(legit)} legítimas ({n_curadas} curadas BR + {len(legit_top)} top whitelist).")

    # ----- Phishing -----
    print(f"Carregando blacklist.json...")
    blacklist = carregar_blacklist()
    print(f"  {len(blacklist):,} URLs na blacklist.")

    # Distribuição: 60% imita marcas, 25% sintéticas, 15% amostra geral
    n_marcas_alvo = int(n_phish_alvo * 0.60)
    n_sint = min(len(PHISHING_SINTETICAS), int(n_phish_alvo * 0.25))
    n_geral = n_phish_alvo - n_marcas_alvo - n_sint

    todas_marcas = MARCAS_BR + MARCAS_GLOBAIS
    rng.shuffle(todas_marcas)
    n_por_marca = max(2, n_marcas_alvo // len(todas_marcas) + 1)
    phish_marcas = amostra_phishing_marcas(blacklist, todas_marcas, n_por_marca, rng, n_marcas_alvo)
    print(f"  Selecionadas {len(phish_marcas)} phishing imitando marcas conhecidas.")

    phish_sint = [
        {"url": url, "label": "phishing", "fonte": "sintetica", "nota": nota}
        for url, nota in PHISHING_SINTETICAS[:n_sint]
    ]
    print(f"  Selecionadas {len(phish_sint)} phishing sintéticas.")

    evitar = {p["url"].replace("http://", "").replace("https://", "") for p in phish_marcas}
    phish_geral = amostra_phishing_geral(blacklist, n_geral, rng, evitar)
    print(f"  Selecionadas {len(phish_geral)} phishing de amostra geral.")

    phish = phish_marcas + phish_sint + phish_geral

    # ----- Embaralhar e escrever -----
    todas = legit + phish
    rng.shuffle(todas)

    out_path = Path(args.output)
    with out_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["url", "label", "fonte", "nota"])
        writer.writeheader()
        writer.writerows(todas)

    n_legit = sum(1 for r in todas if r["label"] == "legitimate")
    n_phish = sum(1 for r in todas if r["label"] == "phishing")
    print(f"\nEscrito {len(todas)} URLs em {out_path}")
    print(f"  Legítimas: {n_legit}")
    print(f"  Phishing:  {n_phish}")


if __name__ == "__main__":
    main()
