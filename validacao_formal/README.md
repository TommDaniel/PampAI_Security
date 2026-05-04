# Validação formal — DomURLs-BERT URL+WHOIS vs multimodal

> Resolve a pendência metodológica reconhecida em `Resultados.tex` §5.5 e §5.6
> da monografia: *"Uma rodada formal, com lista pré-registrada e medição
> automática de Verdadeiros Positivos, Falsos Positivos e latência fim-a-fim,
> fica como trabalho futuro."*

Este pacote roda os **dois modelos BERT** (URL+WHOIS adotado e multimodal não
adotado) sobre uma **lista pré-registrada** de URLs com rótulos verdadeiros,
no estilo da Tabela 7 do TCC (BERT puro / CatBoost puro / Cascata) — só que
agora comparando os dois backbones BERT entre si.

## Estrutura

```
validacao_formal/
├── README.md
├── requirements.txt
├── gerar_lista.py          ← gerador determinístico de lista_validacao.csv
├── lista_validacao.csv     ← 1946 URLs pré-registradas (1000 legítimas + 946 phishing)
├── validacao_formal.py     ← script principal
├── whois_cache.json        ← criado automaticamente na 1ª execução
└── resultados/
    └── validacao_formal.json   ← JSON detalhado (criado pelo script)
```

## Pré-requisitos

- Python 3.10+
- PyTorch + transformers (GPU recomendada; funciona em CPU também)
- Acesso de rede para a coleta WHOIS (apenas na 1ª execução; depois fica em cache)

Instalação no PC de teste:

```bash
cd PampAI_Security/validacao_formal/
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Como rodar

### Caso típico (ambos modelos disponíveis localmente)

```bash
python validacao_formal.py \
    --model-urlonly    /caminho/para/TCC-Finetuning-DomURLs-BERT/modelo-final \
    --model-multimodal /caminho/para/models/DomURLs-BERT-multimodal
```

### Sem coleta WHOIS (mais rápido; usa `[WHOIS] unknown` para todas)

```bash
python validacao_formal.py \
    --model-urlonly    /caminho/.../modelo-final \
    --model-multimodal /caminho/.../DomURLs-BERT-multimodal \
    --no-whois
```

### Com limiar diferente (default 0,65 — o usado em produção)

```bash
python validacao_formal.py ... --threshold 0.5
```

## O que o script faz

1. **Lê** a lista pré-registrada `lista_validacao.csv` (URL, label, fonte, nota).
2. **Coleta** WHOIS de cada domínio uma única vez, salvando em `whois_cache.json`
   para reuso em execuções futuras (acelera a 2ª rodada).
3. **Carrega** ambos os modelos via `transformers` (sem passar pela API
   FastAPI — isolando latência de rede).
4. **Roda** inferência sobre as 195 URLs, **duas vezes** (uma por modelo),
   usando o mesmo `text_input` para ambos:

       [URL] {url} {whois_txt} [EXTRA] none

5. **Mede** latência de cada inferência via `time.perf_counter` (em ms).
6. **Calcula** TP, FP, TN, FN, Precisão, Recall, F1, FPR, MCC e percentis
   P50/P95/P99 da latência.
7. **Imprime** tabela comparativa formatada para registro no TCC.
8. **Salva** JSON detalhado com resultados individuais por URL e listagem dos
   falsos positivos/falsos negativos de cada modelo, ordenados pela
   probabilidade.

## Decisão metodológica

Ambos modelos recebem **exatamente o mesmo `text_input`** (formato URL+WHOIS).
Isso isola a comparação à diferença de **pesos treinados**, que é o que
queremos avaliar: o multimodal foi treinado com mistura de URLs+WHOIS e
features tabulares do dataset GregaVrbancic; o URL+WHOIS foi treinado
exclusivamente com URLs+WHOIS. A pergunta é se essa diferença de regime de
treinamento, sem features tabulares disponíveis em produção, gera diferença
no comportamento operacional sobre URLs reais cotidianas.

Esta condição reflete a operação real da extensão: ao receber uma URL nova,
o servidor não tem como calcular as features tabulares do GregaVrbancic
(número de hifens, ponto, vogais no domínio, etc.) com a mesma definição
exata usada no treino, então ambos os modelos rodam sobre o mesmo input
mínimo `[URL] {url} {whois_txt} [EXTRA] none`.

## Lista pré-registrada

`lista_validacao.csv` traz **1946 URLs** geradas deterministicamente
(``random.seed = 42``) pelo script ``gerar_lista.py``, a partir das
fontes consolidadas do próprio projeto:

**1000 legítimas** (do mais para o menos prioritário):
- 46 URLs curadas BR (bancos, governo, universidades, viagem, saúde,
  serasa, etc.) — todas as URLs operacionais relevantes do contexto
  brasileiro do trabalho.
- 273 do `curated_br` da whitelist (curadoria nacional).
- 244 do `tranco` (top sites globais — Tranco List, Le Pochat et al. 2019).
- 283 do `majestic` (Majestic Million).
- 154 do `curated_global` (curadoria global de big-tech).

**946 phishing** (todos retirados das mesmas fontes da blacklist
embarcada na extensão — PhishTank, OpenPhish, URLhaus, PhishStats,
Phishing.Database):
- 546 URLs reais que **imitam marcas conhecidas** — distribuídas entre
  marcas globais (paypal, google, amazon, microsoft, apple, netflix,
  facebook, instagram, whatsapp, linkedin, twitter, spotify, outlook,
  office365, icloud, dropbox, github, ebay, chase, wells fargo, bofa,
  citi) e marcas brasileiras (bradesco, itaú, caixa, nubank, santander,
  banco do brasil, mercado livre, magalu, americanas, correios, gov.br,
  receita, detran, submarino, casas bahia, shopee).
- 357 URLs reais de amostra geral da blacklist (sem viés de marca,
  para cobertura ampla).
- 43 URLs sintéticas variadas (IP-based, typosquatting/homóglifos,
  subdomínios suspeitos, domínios verborrágicos, TLDs descartáveis
  `.tk/.ml/.ga/.cf/.xyz/.top`).

Para regerar a lista (com a seed fixa 42, os resultados são reprodutíveis):

```bash
python gerar_lista.py --total 2000
```

A escala (~2000 URLs) é ~20× maior do que as rodadas qualitativas
(`validacao_modelo.json` 62 URLs, `validacao_cascata.json` 101 URLs)
e dá percentis de latência estáveis e cobertura suficiente para
estimativas confiáveis de FPR e Recall sobre o conjunto.

> **Tempo esperado de execução** (referência, GPU NVIDIA T4 / Colab):
> - Coleta WHOIS de ~1300 domínios únicos: 30–60 min na 1ª rodada
>   (cacheado nas seguintes via `whois_cache.json`).
> - Inferência: ~6–10 min para os 2 modelos sobre 1946 URLs (em CPU
>   pode dobrar; em GPU rápida fica no minuto único).
>
> Para acelerar testes iniciais, use `--no-whois` (todas as URLs
> recebem `[WHOIS] unknown`).

## Saída esperada

```
==========================================================================
VALIDAÇÃO FORMAL — COMPARAÇÃO ENTRE MODELOS
==========================================================================
Métrica                         URL+WHOIS               Multimodal
--------------------------------------------------------------------------
URLs avaliadas                  1946                    1946
    Legítimas                   1000                    1000
    Phishing                    946                     946
Verdadeiros Positivos (VP)      …                       …
Falsos Positivos (FP)           …                       …
Acurácia                        0.xxxx                  0.xxxx
Precisão                        0.xxxx                  0.xxxx
Revocação                       0.xxxx                  0.xxxx
F1                              0.xxxx                  0.xxxx
FPR                             xx.xx%                  xx.xx%
MCC                             0.xxxx                  0.xxxx
Latência média (ms)             …                       …
Latência P50 (ms)               …                       …
Latência P95 (ms)               …                       …
Latência P99 (ms)               …                       …
==========================================================================
```

Em seguida o script lista, por modelo, os 10 principais falsos positivos
(legítimas com maior probabilidade de phishing) — informação direta para
a discussão da §5.5 do TCC.

## Depois de rodar

1. Trazer o arquivo `resultados/validacao_formal.json` de volta para o
   PC da escrita.
2. Os dados serão analisados na conversa com Claude para alimentar:
   - Uma nova subseção em `Resultados.tex` §5.5 com a tabela comparativa
     formal (estilo Tabela 7), eliminando a frase "rodada formal não
     executada" da §5.5/§5.6.
   - Discussão atualizada do trade-off URL+WHOIS vs multimodal com
     evidência empírica simétrica.
