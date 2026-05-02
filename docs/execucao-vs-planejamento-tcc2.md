# Execução vs. Planejamento — TCC II

**Data:** 2026-04-27
**Autor:** Daniel Felipe Tomm
**Orientador:** Prof. Sandro da Silva Camargo
**Referência do planejamento:** `PPEC-TCC2-DanielTomm/Projeto_TCC2.pdf`
**Referência da execução:** repositório `PampAI_Security` (50 commits, 2026-03-28 → 2026-04-17)

Este documento confronta o planejamento submetido ao PPEC do TCC II com o que efetivamente foi entregue no repositório `PampAI_Security`. O objetivo é registrar quais objetivos foram cumpridos, quais sofreram pivôs e por quê, o que foi entregue além do escopo, e o que ainda está em aberto.

---

## 1. Síntese executiva

| Eixo | Status |
|---|---|
| Premissa original (modelo leve local + fallback API) | **Pivotada** — modelo local foi removido após validação empírica |
| Arquitetura final | Extensão "fina" (whitelist/blacklist/cache) + API com cascata BERT + CatBoost |
| Detecção de phishing em URLs | **Cumprido**, com modelo melhor que o planejado |
| Detecção de phishing em e-mail | **Adicional** — não estava no escopo, foi entregue |
| Plataforma enterprise (dashboard, multi-tenant, alertas) | **Adicional** — não estava no escopo, foi entregue |
| Avaliação em navegação controlada | **Parcial** — testes de integração e benchmarks; sem campo formal |
| Redação final do TCC II | **Em estado de proposta** — texto está congelado no plano inicial; não reflete a execução (ver §7.6) |

O projeto entregou um superset do escopo original. A principal mudança conceitual foi abandonar a **decisão local com modelo leve no navegador** (item central da proposta no PDF) por uma combinação de **listas locais + cache + decisão remota com modelo robusto**, depois que a validação mostrou que o modelo leve embarcado disparava chamadas à API com tanta frequência que sua existência não justificava o custo de manutenção, tamanho do bundle e complexidade.

---

## 2. O que foi planejado no Projeto_TCC2.pdf

**Título:** "Detecção de Phishing em Tempo Real no Navegador por Extensão Web com Aprendizado de Máquina."

**Premissa central:** decisão local no navegador via modelo leve, com fallback condicional para um modelo robusto (DomURLs-BERT) hospedado em API REST quando a confiança do modelo leve fosse baixa.

### 2.1 Objetivos específicos do TCC II

1. Validar comparativamente os modelos candidatos do TCC I e definir o modelo leve final (acurácia, FPR, latência).
2. Estudo de **ablation** dos indicadores (URL, DOM, combinações).
3. **Exportar o modelo leve para JavaScript ou WebAssembly** e definir limiares operacionais.
4. Investigar a viabilidade de um modelo robusto **transformer (DomURL-BERT)** como serviço de fallback remoto via API.
5. Implementar a **extensão Manifest V3 com Plasmo**, integrando coletor + módulo de decisão local + fallback remoto **condicional**.
6. Avaliar a extensão em cenários de navegação controlada (taxa de detecção, FPR, latência, comportamento da interface de alerta).
7. Consolidar os artefatos (código, modelos, scripts, documentação) em pacote reprodutível.

### 2.2 Cronograma planejado (16 semanas)

| Período | Atividade | Situação no PDF |
|---|---|---|
| Semanas 1-2 | Revisão e preparo de ambiente | Concluído |
| Semanas 3-4 | Coleta/curadoria de URLs brasileiras | Concluído |
| Semanas 5-6 | Engenharia de indicadores (URL + DOM) | Concluído |
| Semanas 7-8 | Treinamento de modelos leves (LR/RF/XGBoost/LightGBM) | Concluído |
| Semanas 9-10 | Experimentos com modelo robusto como fallback | Concluído |
| Semana 11 | Validação comparativa, ablation, latência | Em andamento |
| Semana 12 | Exportação do modelo leve, thresholds | Em andamento |
| Semanas 13-14 | Implementação Manifest V3 + Plasmo + fallback | Em andamento |
| Semana 15 | Avaliação em navegação controlada | Pendente |
| Semana 16 | Consolidação e redação final | Pendente |

---

## 3. O que foi efetivamente executado

A execução pode ser dividida em quatro grandes blocos, cada um marcado por um PRD (Product Requirements Document) e por uma rodada de ~14-15 user stories registradas em `tasks/`. O histórico do git e o `progress.txt` mostram o seguinte fluxo:

### 3.1 Bloco 1 — Migração para arquitetura cliente-servidor (PRD `prd-anti-phishing-domurls-bert-api`)

**Período:** 2026-03-28 (todos os 14 commits no mesmo dia, depois do `Initial commit: existing codebase`).

Trata-se do **primeiro pivô**. O ponto de partida (`10165ab Initial commit`) trazia o estado herdado do TCC I: um modelo GBM exportado em ONNX (~95 MB) rodando no navegador via `onnxruntime-web`, com 51 features extraídas no cliente. As 14 user stories migram esse desenho para a arquitetura final:

| US | Entrega |
|---|---|
| US-001 | Reescrita do `app.py` (FastAPI) com `PhishingRequest` + `PhishingResponse`; remoção de toda a lógica de RF/ensemble |
| US-002 | Correção crítica do `create_feature_text` para o formato de treino do BERT (`[URL]...[WHOIS]...[EXTRA]...`); `max_length` corrigido de 512 para 128 |
| US-003 | `server_features.py` — extração assíncrona de WHOIS (cache + live), DNS (MX/NS/SPF/A) e redirects HTTP via `asyncio.gather` |
| US-004 | Endpoint batch `POST /predict-batch` com tokenização em lote |
| US-005 | Dockerização da API (modelo de 422 MB montado como volume) |
| US-006 | `clientFeatures.ts` — extração de **11 features** no cliente (em vez das 51 anteriores) |
| US-007 | `api.ts` — cliente HTTP com timeout 5s, fallback offline, URL configurável via `chrome.storage.sync` |
| US-008 | `cache.ts` — cache em `chrome.storage.local` com TTL diferenciado (24h legítimo / 7d phishing) e LRU em 5000 entradas |
| US-009 | `background.ts` — orquestrador do pipeline `whitelist → blacklist → cache → API` |
| US-010 | `detector.ts` content script — banner vermelho (phishing) / laranja (confiança < 70%) / sem banner (legítimo ou offline = fail-open) |
| US-011 | `popup.tsx` reescrito (sem ONNX), com cartão de resultado, indicador online/offline, settings de URL e clear cache |
| US-012 | `logger.ts` — campo `source` no `DecisionLog` |
| US-013 | Limpeza: remoção de `onnxruntime-web`, `tldts`, `inference.ts`, `features.ts`, todos os `.onnx` e `.wasm`, CSP `wasm-unsafe-eval`. Tamanho da extensão **caiu de ~95 MB para ~26 MB** |
| US-014 | 61 testes de integração end-to-end cobrindo 8 cenários (blacklist hit, whitelist hit, cache hit, API offline, recovery, etc.) |

Ao final desse bloco, `a31ceb2 feat: cascade architecture (BERT + CatBoost) with full validation` consolidou a **cascata final** em produção: DomURLs-BERT decide direto se P(phishing) ≥ 0.85 ou ≤ 0.15; em zona incerta (0.15-0.85) o **CatBoost** entra com features enriquecidas (cliente + WHOIS + DNS + redirects) e o score combinado é `0.6×BERT + 0.4×CatBoost`, com threshold final em 0.65.

### 3.2 Bloco 2 — Análise de phishing em e-mail (PRD `prd-email-phishing-analysis`)

**Período:** 2026-03-29 a 2026-04-04. **14 user stories.**

Esta feature **não estava no escopo do PDF** mas foi adicionada após validação positiva do bloco 1. Resumo:

- **US-001 a US-008 (API):** modelos `EmailRequest`/`EmailResponse`; carga de **DistilBERT** (`cybersectony/phishing-email-detection-distilbert_v2.4.1`, 66M params, F1 99.58%) e **MarianMT** (`Helsinki-NLP/opus-mt-tc-big-pt-en`) no startup; endpoint `POST /analyze-email`; detecção de idioma com `langdetect` + tradução PT→EN; análise das URLs do corpo (sem cascata, apenas BERT); combinação ponderada (60% e-mail + 40% URL, com boost para 0.9 quando alguma URL tem confiança > 80%); três rótulos: **PHISHING (>0.6) / SUSPICIOUS (0.4-0.6) / LEGITIMO (<0.4)**; Dockerfile pré-baixa os modelos no build.
- **US-009 a US-012 (Extensão):** interface `EmailAnalysisResponse` no `api.ts`; novo content script `webmail-detector.ts` que injeta em Gmail (`mail.google.com`) e Outlook (`outlook.{live,office365,office}.com`) com hierarquia de seletores (específicos primeiro: `h2.hP`, `div.a3s.aiL`, `span.gD[email]`; fallback semântico: `[role="main"]`, `[data-message-id]`, `[aria-label]`); MutationObserver para SPA, debounce 500ms e hash do último e-mail para evitar reanalise; handler `ANALYZE_EMAIL` no background; popup mostra cartão de e-mail (PHISHING / SUSPICIOUS / LEGÍTIMO) com lista de URLs do corpo, idioma detectado e flag de tradução.
- **US-013 a US-014:** notebook `benchmark_email_phishing.ipynb` com métricas (accuracy, F1, precision, recall, AUC-ROC, confusion matrix) e comparação com alternativa multilíngue; testes de integração end-to-end.

Detalhes em `docs/analise-branch-email-phishing.md` (autoria do projeto).

### 3.3 Bloco 3 — Plataforma Enterprise (PRD `prd-enterprise-backend`)

**Período:** 2026-04-09. **15 user stories.**

Também **fora do escopo do PDF**. Transforma o sistema stateless num produto multi-tenant com visibilidade centralizada. Itens entregues:

- **US-001 (Persistência):** PostgreSQL 16 + SQLAlchemy 2.0 async + asyncpg; tabelas `organizations`, `users`, `analysis_events`; migrations em `phishing-api/migrations/` (`001_init.sql`, `002_user_email.sql`).
- **US-002 (AuthN):** autenticação por **API Key** por organização (header `X-API-Key`, hash SHA-256); CLI `manage.py` com `create-org`, `list-orgs`, `rotate-key`; modo anônimo preservado quando o header está ausente.
- **US-003 / US-004 (Eventos):** `POST /events` para persistência explícita e auto-persistência transparente nos endpoints `/predict` e `/analyze-email` quando há `X-API-Key` + `X-User-Email`.
- **US-005 (Relatórios):** `GET /reports/{org_id}/summary` (período 7/30/90 dias) com top users, top domains, daily counts, eventos paginados.
- **US-006 / US-007 / US-008 (Alertas):** `alerts.py` com `send_alert()` (webhook, timeout 5s, fire-and-forget) e `send_email_alert()` (SMTP via env vars); `PATCH /orgs/{org_id}/alerts` para configuração.
- **US-009 / US-010 (Dashboard):** endpoints `/dashboard/{org_id}/{stats,events,users}`; frontend single-page em `phishing-api/dashboard/index.html` (Chart.js, Tailwind via CDN) servido pelo próprio FastAPI em `/dashboard-ui/`. Login por API key, cards de métricas, série temporal, tabela paginada com filtros.
- **US-011 / US-012 / US-013 (Extensão Enterprise):** `assets/managed_schema.json` para `chrome.storage.managed`; `identity.ts` com fallback `managed → sync`; `api.ts` injeta `X-API-Key` e `X-User-Email`; `background.ts` dispara `POST /events` em fire-and-forget após cada análise; `logDecision()` ativado.
- **US-014 / US-015 (Infra/Docs):** Docker Compose completo (postgres + api + dashboard servido por nginx); `.env.example`; documentação de deploy enterprise com template de GPO Windows / managed preferences macOS.

Detalhes em `docs/pesquisa-produto-enterprise.md`.

### 3.4 Bloco 4 — Correções e fechamento

- `9f07eb5 fix: correcoes de atribuicao, origem, alvo e falso-positivo em emails` (2026-04-15) — adiciona `migrations/002_user_email.sql` e ajusta atribuição/origem.
- `ccd4c06 chore: setup PampAI Security` (2026-04-17) — README final, submódulo da monografia, `docs/comparativo-ferramentas-phishing.md`, `scripts/atualizar_listas.py`, `test_performance.py`, PRD enterprise.
- `2f4ec7b chore: add .gitignore` (2026-04-17) — exclui datasets grandes e artefatos.

---

## 4. Cumprimento dos objetivos do PDF, item a item

| # | Objetivo do PDF | Cumprimento | Observação |
|---|---|---|---|
| 1 | Validar comparativamente modelos candidatos do TCC I e definir modelo leve final | **Cumprido** (com pivô) | `benchmark_modelos_leves.ipynb` registra LR (F1 72.0%), Linear SVM (71.7%), RF (84.2%) e GBM (83.3%); `treino_gbm_brasileiro.ipynb` selecionou o GBM com **F1 87.27%, AUC-ROC 94.43%, MCC 0.7432** no dataset BR de 660k URLs. **Mas:** este modelo deixou de ser o decisor primário (ver pivô abaixo) |
| 2 | Estudo de ablation dos indicadores | **Parcial / Cumprido** | Os notebooks de benchmark contêm comparações por subconjuntos de features (URL-only vs. DOM vs. combinado). O *paper* original foi consumido como referência; o estudo formal de ablation aparece nos notebooks `benchmark_*.ipynb` mas o relatório consolidado fica para o texto da monografia |
| 3 | Exportar modelo leve para JS/WebAssembly e definir limiares | **Cumprido e depois revertido** | A primeira versão da extensão *de fato* exportava o GBM via `modelo_phishing_ort14.onnx` (`onnxruntime-web` + WASM) e definia thresholds locais. **A US-013 deletou tudo isso** após o pivô descrito na seção 5. O artefato existe historicamente (TCC I/herdado), mas não está mais em produção |
| 4 | Avaliar DomURL-BERT como fallback remoto via API | **Cumprido com escopo expandido** | DomURLs-BERT foi avaliado *e adotado* — porém **como modelo primário**, não como fallback. O fallback passou a ser o **CatBoost** dentro de uma cascata, acionado quando o BERT fica em zona incerta (P entre 0.15 e 0.85). API REST com FastAPI, Docker, batch endpoint, server features — todos entregues |
| 5 | Implementar extensão Manifest V3 com Plasmo, integrando coletor + decisão local + fallback condicional | **Cumprido com pivô** | MV3 + Plasmo + content script + background MV3 + popup React: tudo entregue. A "decisão local" virou `whitelist + blacklist + cache` (sem ML local). O "fallback condicional" virou *cascata server-side* (BERT → CatBoost) — o cliente sempre consulta a API quando whitelist/blacklist/cache não resolvem |
| 6 | Avaliar extensão em cenários de navegação controlada | **Parcial** | Existem 61 testes de integração end-to-end (`test_integration.py`) cobrindo 8 cenários funcionais; testes de performance (`test_performance.py`); validação dos modelos em datasets (UMUDGA, UTL_DGA, DNS Tunneling, Grambedding, LNU_Phish, PhiUSIIL — relatadas como referência do paper). **Falta:** sessão formal de navegação controlada com URLs reais de phishing × páginas legítimas, medindo TPR/FPR/latência da extensão completa em campo. Esse é o típico conteúdo da Semana 15 do cronograma |
| 7 | Consolidar artefatos em pacote reprodutível | **Cumprido** | `README.md` raiz; subdirs com READMEs; `docker-compose.yml`; `requirements.txt`; PRDs e `progress.txt` versionados; submódulo `Monografia-TCC`; scripts de coleta/atualização. Reprodutibilidade: `docker compose up -d` para a API; `npm install && npm run build` para a extensão |

---

## 5. Pivôs em relação ao planejamento (e por quê)

### 5.1 Pivô A — Eliminação do modelo leve local

**Planejado:** modelo leve (GBM/ONNX) decide na maioria dos casos no navegador; só consulta API em casos de baixa confiança.

**Observado em campo:** durante a integração, o GBM exportado para ONNX produzia muitos **falsos positivos** e, sobretudo, sua **confiança ficava abaixo do threshold** com frequência alta — o que disparava chamada à API "de fallback" na maioria das navegações. Resultado: o custo (95 MB de bundle, runtime WASM, manutenção de duas inferências) não compensava o benefício (poucos casos efetivamente decididos só localmente).

**Decisão:** remover o modelo local. Manter três camadas instantâneas no cliente — **whitelist** (32k+ domínios curados de Tranco/Majestic + curadoria BR), **blacklist** (774k+ domínios de OpenPhish + PhishTank + URLhaus + PhishStats + Phishing.Database) e **cache** com TTL diferenciado (24h legítimo / 7d phishing) — e enviar à API tudo o que não for resolvido localmente.

**Resultado mensurável:**
- Bundle da extensão caiu de ~95 MB para ~26 MB.
- F1 final do classificador subiu (GBM 87.27% → cascata BERT+CatBoost com DomURLs-BERT atingindo 99%+ nos benchmarks de referência).
- A maior parte das URLs cotidianas é resolvida pelas listas/cache em **O(1)**, sem chamada à API.

Esse pivô está documentado nos commits US-001 a US-014 do bloco 1 e é o motivo do PRD `prd-anti-phishing-domurls-bert-api` se chamar literalmente "Migrate Chrome anti-phishing extension from local GBM/ONNX inference to client-server architecture".

### 5.2 Pivô B — DomURLs-BERT deixa de ser fallback e vira primário

Como consequência direta do pivô A, o BERT robusto deixou de ser "rede de segurança" e passou a ser **o** classificador. Para preservar a ideia de complementaridade entre métodos, foi introduzida uma **cascata server-side**: BERT decide direto quando confiante; em zona cinza, CatBoost com features enriquecidas (WHOIS/DNS/redirects) refina a decisão. Score final: `0.6×BERT + 0.4×CatBoost`, threshold 0.65.

### 5.3 Pivô C — Adição de detecção em e-mail

Não previsto no PDF. Após o produto de URL ficar estável, foi entregue um pipeline completo de e-mail (DistilBERT + MarianMT PT→EN + análise de URLs do corpo + content script para Gmail/Outlook + UI no popup). Detalhes na seção 3.2.

### 5.4 Pivô D — Plataforma enterprise

Também não previsto. O sistema ganhou: PostgreSQL, autenticação por API Key, multi-tenancy (org_id), persistência automática de eventos, dashboard web, alertas (webhook + e-mail), `chrome.storage.managed` para deploy via GPO/MDM, e Docker Compose unificado. Detalhes na seção 3.3.

---

## 6. Funcionalidades entregues além do escopo

| Categoria | Item |
|---|---|
| **Detecção de e-mail** | Endpoint `/analyze-email`, DistilBERT, MarianMT (PT→EN), três rótulos (PHISHING/SUSPICIOUS/LEGITIMO), análise de URLs do corpo, content script Gmail/Outlook, popup com visualização de e-mail |
| **Listas locais robustas** | Blacklist com 774k+ domínios de 5 fontes; whitelist com 32k+ domínios; script `scripts/atualizar_listas.py` para atualização automática |
| **Cascata server-side** | DomURLs-BERT + CatBoost com features cliente + WHOIS + DNS + redirects |
| **Persistência e Auth** | PostgreSQL com SQLAlchemy async, migrations, autenticação por API Key (SHA-256), CLI `manage.py` |
| **Dashboard** | SPA web com Chart.js, login por API key, métricas, série temporal, tabela paginada com filtros |
| **Alertas** | Webhook (Slack/etc.) e e-mail SMTP com template HTML; `PATCH /orgs/{org_id}/alerts` |
| **Deploy enterprise** | `chrome.storage.managed` + JSON Schema, template GPO Windows + managed preferences macOS, docs em `docs/deploy-enterprise.md` |
| **Comparativo de mercado** | `docs/comparativo-ferramentas-phishing.md` posiciona o sistema vs. Google Safe Browsing, Netcraft, SmartScreen e SOTA acadêmico |
| **Análise comercial** | `docs/pesquisa-produto-enterprise.md` mapeia o gap de mercado e roadmap para MVP vendável |
| **Cobertura de testes** | ~12 arquivos de teste no `phishing-api/` (`test_api.py`, `test_auth.py`, `test_alert_configs.py`, `test_auto_persist.py`, `test_dashboard.py`, `test_dashboard_frontend.py`, `test_email_alert.py`, `test_events.py`, `test_integration.py`, `test_performance.py`, `test_reports.py`, `test_webhook.py`) |

---

## 7. Itens do planejamento ainda em aberto

1. **Avaliação formal em navegação controlada (Semana 15 do cronograma)** — falta uma sessão de campo com conjunto de teste reservado de URLs reais (phishing confirmados + páginas legítimas brasileiras), medindo TPR, FPR, latência ponta-a-ponta da extensão e comportamento da UI de alerta. Os testes existentes são unitários e de integração, não medem desempenho de detecção em campo. Os benchmarks reportados (UMUDGA, UTL_DGA etc.) vêm do paper original do DomURLs-BERT, não de uma avaliação independente da implantação.
2. **Estudo de ablation consolidado** — os notebooks têm os elementos, mas falta o relatório formal com tabela de contribuição relativa por grupo de features (URL-only vs. DOM vs. combinações), conforme prometido no objetivo 2.
3. **Texto da monografia (ver §7.6)** — atualmente o maior gap. Texto em estado de proposta, sem refletir nada da execução.
4. **Calibração explícita de probabilidades e thresholds operacionais** — os thresholds estão fixados (0.85/0.15 para a cascata, 0.65 final, 0.6 e-mail, 0.8 boost de URL no e-mail) mas não há documentação consolidada da calibração (`scikit-learn CalibratedClassifierCV` ou similar) e de como os thresholds foram escolhidos a partir da curva precisão-recall.
5. **Reprodutibilidade do pipeline de treino** — os notebooks existem, mas faltam scripts não-interativos e seeds fixadas para garantir reprodutibilidade idêntica em outro ambiente. O `prd.json` e `progress.txt` cobrem o pipeline da API/extensão, não o pipeline de treino.

### 7.6 Estado atual da monografia (`Monografia-TCC/`)

O submódulo está num único commit, **`4f7b85c Initial Overleaf Import`**, importado direto do Overleaf. Cada capítulo foi inspecionado e o quadro é:

| Arquivo | Tamanho | Estado | Observação |
|---|---|---|---|
| `Resumo.tex` | 3.8K | **Desatualizado** | Descreve a "arquitetura híbrida com classificador leve embarcado e modelo mais potente em servidor" e "resultados parciais com classificador baseado em múltiplas árvores de decisão". Refere-se ao desenho do TCC I, não à arquitetura final |
| `Introducao.tex` | 2.8K | **Desatualizado** | Cita "verificador leve no navegador e outro, mais robusto, no servidor para casos de dúvida" — descrição que já não corresponde à solução implementada |
| `Problema.tex` | 5.4K | Provável OK | Texto de motivação; não foi inspecionado em detalhe mas assunto é estável (problema de phishing) |
| `Objetivos.tex` | 1.1K | **Genérico, mas válido** | Lista 7 objetivos em alto nível compatíveis com a execução, exceto pelo viés "decisão local prioritária" no objetivo geral |
| `Organizacao.tex` | 1.0K | Provável OK | Estrutural |
| `Revisao.tex` | 28.8K | Desconhecido (não inspecionado) | Revisão de literatura; conteúdo provavelmente reaproveitável |
| `Metodologia.tex` | 28.5K | **Desatualizado** | Descreve modelos leves (LR, RF, gradient boosting) sendo treinados para execução no navegador, ablation URL vs. DOM, harness de latência local. Toda a descrição metodológica reflete o **plano original**, não o que foi feito (BERT em servidor, cascata, listas, e-mail, dashboard) |
| `Desenvolvimento.tex` | 57.8K | **Desatualizado / em estado de plano** | É o capítulo mais volumoso e descreve "Visão Geral e Entregáveis", "Planejamento e Rastreabilidade", MVP — tudo em tempo verbal de plano. Os 12 entregáveis (E1-E12) descrevem a solução **idealizada** (E1: extensão com modelo leve embarcado, E2: modelo leve exportado para JS/WASM, E3: serviço de inferência pesado opcional). Não há seção descrevendo a arquitetura efetivamente entregue |
| `Resultados.tex` | 2.2K | **Crítico** | Inteiro em tempo futuro: "Espera-se que..." Não há nenhum número obtido — F1 87.27%, AUC 94.43% do GBM final, métricas da cascata BERT+CatBoost, F1 do DistilBERT no benchmark de e-mail, latências medidas, etc. Não está nem incluído no `TEXTO-Principal.tex` (a lista de `\input` no documento principal pula direto de `Desenvolvimento.tex` para `Conclusoes.tex`) |
| `Conclusoes.tex` | 5.0K | **Desatualizado** | Lista como "Próximos Passos" várias coisas que **já foram feitas**: validação cruzada estratificada, comparar LR/XGBoost/LightGBM com RF, ajustar thresholds via ROC, estudo de feature importance e ablação. Trata o GBM/RF como "modelo preliminar" quando o produto final é uma cascata BERT+CatBoost. Cita PhishTank com 11.055 amostras como dataset, mas a execução usou 660k URLs brasileiras |
| `Cronograma-TCC2.tex` | 3.7K | **Desatualizado** | Reproduz o cronograma do PDF (16 semanas, modelo leve no navegador, exportação JS/WASM). Está incluído via `\input` em `Conclusoes.tex` — ou seja, o cronograma do plano aparece dentro das conclusões |
| `TEXTO-Principal.tex` | 5.6K | OK estruturalmente | Inclui `Resumo`, `Introducao`, `Problema`, `Objetivos`, `Organizacao`, `Revisao`, `Metodologia`, `Desenvolvimento`, `Conclusoes`. **Não inclui `Resultados.tex`** (que existe no diretório mas não é referenciado) |

**Conclusão sobre a monografia:** o texto atual é essencialmente uma versão expandida da proposta do PPEC, congelada antes da execução. Para fechar o TCC II é preciso, no mínimo:

1. **Reescrever o `Resumo.tex`** para descrever a arquitetura final (extensão + listas + cache + API com cascata BERT+CatBoost; análise de e-mail; plataforma enterprise) e citar resultados obtidos.
2. **Atualizar `Introducao.tex`** removendo o framing de "modelo leve embarcado + fallback servidor" e introduzindo o pivô como decisão de engenharia.
3. **Reescrever ou ampliar `Desenvolvimento.tex`** para descrever a solução **realmente entregue**: pipeline da extensão (whitelist/blacklist/cache/API), API FastAPI com cascata, integração de e-mail (DistilBERT + MarianMT + content scripts Gmail/Outlook), persistência PostgreSQL, autenticação por API key, dashboard, alertas. O conteúdo dos PRDs em `tasks/` e dos docs em `docs/` (`analise-branch-email-phishing.md`, `comparativo-ferramentas-phishing.md`, `pesquisa-produto-enterprise.md`) já é a base bruta dessa redação.
4. **Substituir `Resultados.tex`** por um capítulo de resultados *obtidos*, com:
   - Tabela do benchmark de modelos leves (LR/SVM/RF/GBM) — já existe em `benchmark-modelos/benchmark_modelos_leves.ipynb` e está resumida no README.
   - Métricas finais do GBM brasileiro (F1 87.27%, AUC 94.43%, MCC 0.7432).
   - Métricas da cascata BERT+CatBoost em produção (precisa rodar avaliação no conjunto de teste).
   - Benchmark do DistilBERT de e-mail (F1, accuracy, AUC-ROC, matriz de confusão) — `benchmark_email_phishing.ipynb`.
   - Latências P50/P95 da API (existe `test_performance.py`).
   - **Adicionar `\input{Textos/Resultados}`** no `TEXTO-Principal.tex` entre `Desenvolvimento` e `Conclusoes`.
5. **Reescrever `Conclusoes.tex`** — reposicionar como "Próximos Passos" itens que ainda não foram feitos (avaliação em campo, calibração formal, teste de carga, onboarding self-service, etc.), removendo os que já foram executados. Atualizar as Limitações para refletir as decisões de projeto reais (ex.: ausência de modelo local foi escolha justificada, não limitação de recurso).
6. **Decidir o que fazer com `Cronograma-TCC2.tex`** — remover a inclusão do cronograma original dentro das Conclusões e substituir por um quadro "Cronograma Planejado vs. Executado" que registre os pivôs da Seção 5 deste documento.
7. **Reaproveitar `Metodologia.tex`** mantendo a parte de classificação da pesquisa (aplicada/quantitativa/experimental/exploratória), métricas de avaliação e aspectos éticos, mas reescrevendo as seções de "Treinamento e Ajuste de Modelos" e "Avaliação" para a metodologia que foi de fato aplicada.

A boa notícia é que **toda a matéria-prima existe** no repositório (PRDs, `progress.txt`, três `docs/*.md`, README, notebooks, código). O trabalho restante é majoritariamente de redação e organização, não de geração de novo conteúdo técnico.

---

## 8. Mapeamento commit ↔ user story (referência rápida)

A tabela abaixo registra a ordem cronológica de execução. Todas as US do bloco 1 foram empacotadas no mesmo dia (`2026-03-28`) — efeito do uso intensivo de agentes Ralph na implementação; a evolução real de produto se dá nos blocos 2, 3 e 4.

| Bloco | Commits | Período |
|---|---|---|
| Inicial (TCC I herdado) | `10165ab` | 2026-03-28 |
| Bloco 1 — Migração para cliente-servidor (PRD URL+DomURLs-BERT) | `3915149` → `03b029e` (US-001 a US-014) + `a31ceb2` (cascade) | 2026-03-28 |
| Bloco 2 — Análise de e-mail | `262c471` → `b2349e0` (US-001 a US-014) | 2026-03-29 → 2026-04-04 |
| Bloco 3 — Enterprise | `f737b1b` → `e663031` (US-001 a US-015) | 2026-04-09 |
| Bloco 4 — Correções e setup do repo | `9f07eb5`, `ccd4c06`, `2f4ec7b` | 2026-04-15 → 2026-04-17 |

---

## 9. Conclusão

Os sete objetivos do TCC II foram atingidos no espírito, com dois ajustes importantes em relação ao desenho original:

1. A **decisão local com modelo leve** foi substituída por **listas locais + cache + decisão remota com cascata**, motivada por evidência empírica (o modelo leve disparava o fallback com tanta frequência que sua existência local não se justificava). O resultado foi um produto mais simples no cliente, mais leve em bundle, e com qualidade de detecção superior.
2. O **escopo se expandiu** em três direções não previstas (e-mail, plataforma enterprise, alertas/dashboard), o que posiciona o trabalho não apenas como uma extensão acadêmica mas como um produto enterprise comparável a Netcraft / SmartScreen / Cofense — diferencial documentado em `docs/comparativo-ferramentas-phishing.md`.

A entrega de engenharia está concluída e excede o escopo planejado. **A pendência crítica é a redação da monografia** (`Monografia-TCC/`), que hoje está congelada no estado de proposta — não reflete os pivôs, a arquitetura final, o escopo expandido nem os resultados quantitativos obtidos. O detalhamento por capítulo está na §7.6. Restam ainda **avaliação em navegação controlada (Semana 15)** e **estudo de ablation consolidado**, ambos com matéria-prima parcialmente disponível no repositório mas exigindo nova rodada experimental.
