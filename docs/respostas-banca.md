# Respostas às perguntas da banca — execuções e resultados

Documento consolidando as perguntas da banca que exigiram execução de código,
com os scripts usados, o que cada um faz e os resultados medidos. Todas as
execuções foram feitas em **2026-05-31**, em **CPU (sem GPU)**, na máquina do autor.

> Observação metodológica recorrente: onde há sobreposição treino-teste
> (contaminação), os números são tratados como **teto otimista**, não como
> desempenho de campo. Isso vale para Q2 e Q3.

---

## Q2 — FPR sobre URLs legítimas disjuntas do treino

**Pergunta:** a FPR de ~6,52% da Tabela 8 inclui URLs legítimas que estavam no
treino do DomURLs-BERT (contaminação). Qual a FPR só sobre as legítimas inéditas?

- **Script:** `validacao_formal/recalcular_fpr_disjunta.py`
- **Resultado:** `validacao_formal/resultados/fpr_disjunta.json`
- **Como:** carrega `kmack/Phishing_urls` (train+valid), marca as legítimas da
  rodada formal vistas no treino e recalcula a FPR nas disjuntas (limiar 0,65).

| Subconjunto | FP / total | FPR |
|---|---|---|
| Todas legítimas (Tabela 8) | 66 / 1013 | 6,52% |
| Contaminadas (vistas no treino) | 7 / 306 | 2,29% |
| **Disjuntas (inéditas) — resposta Q2** | 59 / 707 | **8,35%** |

**Conclusão:** removida a contaminação, a FPR **sobe** para **8,35%** — o modelo
erra menos nas URLs que já viu (2,29%) do que nas inéditas (8,35%). O valor 8,35%
é o honesto para a Seção de Limitações.

---

## Q4 — Captura de p_BERT/p_CatBoost por URL e sensibilidade da cascata

**Pergunta:** os pesos da cascata (W=0,6/0,4) e a zona de incerteza (0,15/0,85)
foram bem escolhidos? A rodada formal não salvou p_BERT e p_CatBoost por URL,
impedindo a análise de sensibilidade.

- **Script:** `validacao_formal/q4_cascata_sweep.py`
- **Resultados:** `validacao_formal/resultados/q4_cascata_sweep.json`
  e `q4_probs_por_url.csv` (p_BERT e p_CatBoost por URL)
- **Como:** roda o BERT de produção (`phishing-api/model`) nas 1946 URLs de
  `lista_validacao.csv`; calcula p_CatBoost **apenas nas 178 URLs da zona
  0,15–0,85** (onde o CatBoost de fato pesa), com WHOIS em cache e DNS/redirects
  ao vivo; varre pesos e zonas offline. Limiar de decisão 0,65.

| Cenário | F1 | FPR | MCC |
|---|---|---|---|
| BERT sozinho | 0,9119 | 0,1333 | 0,8267 |
| Cascata W=0,5 (zona 0,15–0,85) | 0,9174 | **0,1145** | 0,8381 |
| **Cascata W=0,6 (produção)** | 0,9170 | 0,1155 | 0,8371 |
| Cascata W=0,7 (zona 0,15–0,85) | **0,9182** | 0,1165 | **0,8395** |
| Cascata W=0,6 zona 0,3–0,7 | 0,9150 | 0,1254 | 0,8331 |
| Cascata W=0,6 zona 0,4–0,6 | 0,9124 | 0,1333 | 0,8278 |

**Conclusões:**
1. A cascata **melhora** sobre o BERT puro — FPR cai de 13,3% para 11,6% e o MCC sobe; o CatBoost na zona corta falsos positivos.
2. **Baixa sensibilidade ao peso:** W ∈ {0,5; 0,6; 0,7} quase não muda as métricas → o W=0,6 de produção é uma escolha robusta.
3. A **largura da zona importa mais que o peso:** estreitá-la (0,4–0,6) colapsa para o BERT puro; a zona ampla 0,15–0,85 de produção é a melhor testada.

**Notas de escopo:** p_CatBoost foi capturado só na zona 0,15–0,85, então o sweep
de zona cobre apenas subconjuntos dessa faixa. As features `tls_*`, `registrar`,
`country_code` e `whois_privacy` são constantes (default) **também em produção**
(o dataclass `ServerFeatures` não as define). A FPR aqui (~12–13%) não é
comparável à da Q2: trata-se de outra lista (1946 URLs, com phishing adversarial).

---

## Q8 — Teste de carga da API sob concorrência

**Pergunta:** quantas requisições simultâneas a API aguenta antes do P95 dobrar?
Qual a latência sob concorrência?

- **Script:** `phishing-api/teste_carga.py`
- **Resultado:** `phishing-api/resultados/teste_carga.json`
- **Como:** sobe a API real (`docker compose up -d`) e bate no `/predict` com
  concorrência crescente (cascata DomURLs-BERT + CatBoost, CPU, single-replica).

| Concorrência | Vazão (req/s) | P50 (ms) | P95 (ms) | P99 (ms) | Erros |
|---|---|---|---|---|---|
| 1 | 20,1 | 44,6 | 67,3 | 147,3 | 0 |
| 2 | 24,1 | 79,6 | 97,5 | 280,7 | 0 |
| 4 | 24,4 | 154,8 | 259,3 | 374,8 | 0 |
| 8 | 23,2 | 308,2 | 545,9 | 778,1 | 0 |
| 16 | 25,1 | 611,0 | 986,5 | 1299,0 | 0 |
| 32 | 23,7 | 1258,5 | 1875,7 | 2124,0 | 0 |

**Conclusões:** a vazão satura em **~24 req/s** (CPU-bound) e não cresce com mais
concorrência; o **P95 dobra já a partir de concorrência 4**; a latência cresce
~linearmente (acima de ~2 simultâneas as requisições só enfileiram); **0 erros**
até 32. Escalar exige réplicas horizontais (~24 req/s por réplica) ou GPU/batching.
P50 morno ~45 ms (a 1ª requisição deu ~900 ms = cold start, descartado).

**Correção de bug:** o `teste_carga.py` original enviava só `{"url": ...}`, mas o
`/predict` exige também `client_features` (11 campos) → 422 em 100% das requisições.
Corrigido com o extrator `extrair_features()` (commit `64c6966`).

---

## Q3 — Avaliação do DistilBERT de e-mail (EN)

**Pergunta:** avaliar o DistilBERT de e-mail sobre um dataset rotulado.

- **Script:** `phishing-api/q3_email_eval.py`
- **Resultado:** `phishing-api/resultados/q3_email_eval.json`
- **Modelo:** `cybersectony/phishing-email-detection-distilbert_v2.4.1` (4 classes)
- **Dataset:** `zefang-liu/phishing-email-dataset` (EN), amostra estratificada de
  4000 e-mails (2000 phishing / 2000 legítimos).
- **Labels:** 0=legitimate_email, 1=phishing_url, 2=legitimate_url, 3=phishing_url_alt
  (phishing = {1, 3}).

| Estratégia de decisão | F1 | Acc | Recall | Prec | FPR | MCC |
|---|---|---|---|---|---|---|
| api_prob1 (prob[1] > 0,7) | 0,9881 | 0,9880 | 0,9965 | 0,9798 | 0,0205 | 0,9761 |
| argmax ∈ {1,3} | 0,9881 | 0,9880 | 0,9965 | 0,9798 | 0,0205 | 0,9761 |
| soma prob[1]+prob[3] > 0,5 | 0,9881 | 0,9880 | 0,9965 | 0,9798 | 0,0205 | 0,9761 |

**Conclusões:**
1. As três estratégias dão **resultado idêntico** — o modelo coloca o phishing
   quase todo na `LABEL_1`, então a `LABEL_3` nunca é decisiva neste dataset e a
   abordagem `prob[1]` da API é equivalente às alternativas.
2. Métricas altíssimas (F1 98,8%), **porém otimistas**: o modelo provavelmente foi
   treinado em fontes que incluem este dataset (contaminação treino-teste) — reportar
   como **teto**, não como desempenho de campo.
3. Cobertura **apenas EN** — não há avaliação em PT (dataset PT rotulado é escasso).

---

## Reprodutibilidade

Todos os scripts rodam em CPU. Dependências já instaladas no host
(`torch` CPU, `transformers`, `catboost`, `datasets`, `dnspython`, `python-whois`,
`httpx`). Q2/Q3 exigem rede (HuggingFace); Q8 exige `docker compose up -d` em
`phishing-api/`. Os JSONs de resultado em `*/resultados/` são os artefatos citados
acima; o CSV por URL da Q4 está versionado via exceção no `.gitignore`.
