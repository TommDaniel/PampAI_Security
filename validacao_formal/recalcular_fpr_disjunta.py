#!/usr/bin/env python3
"""
Q2 da banca — FPR sobre o subconjunto de URLs legitimas DISJUNTAS do treino.

Contexto: a rodada formal reporta FPR ~6,52% sobre 1.013 URLs legitimas, mas
parte delas estava no treino do DomURL-BERT (contaminacao treino-teste). A banca
pede a FPR recalculada APENAS sobre as URLs legitimas inteiramente novas.

Este script:
  1. le as probabilidades por URL da rodada formal (validacao_formal_corrigido.json);
  2. carrega o kmack/Phishing_urls (HuggingFace) e marca quais URLs legitimas da
     rodada formal aparecem nas particoes train+valid (as efetivamente "vistas");
  3. recalcula a FPR sobre as legitimas DISJUNTAS (fora de train+valid).

REQUER: pip install datasets   +   rede (rodar no Colab ou em maquina com internet).
A GPU NAO e necessaria: e tudo recontagem sobre probabilidades ja salvas.

Uso:
    python recalcular_fpr_disjunta.py
"""
import json
import os

RESULT_JSON = os.path.join(os.path.dirname(__file__),
                           "resultados", "validacao_formal_corrigido.json")
THRESHOLD = 0.65  # mesmo limiar de operacao da rodada formal


def normalizar(url: str) -> str:
    """Normaliza para comparacao 'endereco identico': minusculas, sem esquema,
    sem 'www.' inicial e sem barra final. Ajuste aqui se o criterio do projeto
    for outro (a contagem original do TCC foi 187 sobreposicoes / 174 legitimas)."""
    u = str(url).strip().lower()
    for p in ("https://", "http://"):
        if u.startswith(p):
            u = u[len(p):]
    if u.startswith("www."):
        u = u[4:]
    return u.rstrip("/")


def carregar_kmack_seen():
    """Retorna o conjunto de URLs normalizadas das particoes train+valid do kmack
    (as que o modelo efetivamente viu no ajuste)."""
    from datasets import load_dataset
    ds = load_dataset("kmack/Phishing_urls")
    seen = set()
    for split in ("train", "valid"):  # train+valid = vistas no ajuste
        if split in ds:
            for txt in ds[split]["text"]:
                seen.add(normalizar(txt))
    return seen


def main():
    with open(RESULT_JSON, encoding="utf-8") as fh:
        itens = json.load(fh)["resultados_individuais"]["url_whois"]

    legitimas = [it for it in itens if not it["expected_phishing"]]
    print(f"Legitimas na rodada formal: {len(legitimas)}")

    seen = carregar_kmack_seen()
    print(f"URLs unicas em kmack train+valid: {len(seen)}")

    contaminadas, disjuntas = [], []
    for it in legitimas:
        (contaminadas if normalizar(it["url"]) in seen else disjuntas).append(it)

    print(f"Legitimas contaminadas (vistas no treino): {len(contaminadas)}")
    print(f"Legitimas disjuntas (novas):               {len(disjuntas)}")

    def fpr(lst):
        fp = sum(1 for it in lst if it["probability_phishing"] > THRESHOLD)
        return fp, len(lst), (fp / len(lst) if lst else 0.0)

    fp_all, n_all, fpr_all = fpr(legitimas)
    fp_dis, n_dis, fpr_dis = fpr(disjuntas)
    fp_con, n_con, fpr_con = fpr(contaminadas)

    print("\n=== FPR por subconjunto (limiar %.2f) ===" % THRESHOLD)
    print(f"  todas legitimas : FP={fp_all:3d}/{n_all:4d}  FPR={fpr_all:.4f}  (reportado na Tabela 8)")
    print(f"  contaminadas    : FP={fp_con:3d}/{n_con:4d}  FPR={fpr_con:.4f}")
    print(f"  DISJUNTAS       : FP={fp_dis:3d}/{n_dis:4d}  FPR={fpr_dis:.4f}  <-- resposta da Q2")
    print("\nIntegrar o valor de FPR DISJUNTA na Secao de Limitacoes do TCC "
          "(paragrafo da contaminacao treino-teste).")


if __name__ == "__main__":
    main()
