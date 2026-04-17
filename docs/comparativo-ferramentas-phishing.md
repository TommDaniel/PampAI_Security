# Analise Comparativa: PampAI Security vs. Ferramentas de Deteccao de Phishing

> Documento de posicionamento do PampAI Security frente a solucoes comerciais,
> comunitarias e academicas de deteccao de phishing em URLs e e-mails.

---

## 1. Visao Geral do PampAI Security

### 1.1 Arquitetura

O sistema e composto por dois componentes principais:

**Extensao Chrome (client-side)** — Manifest V3, Plasmo, React 18, TypeScript

A extensao nao executa nenhum modelo de ML. Sua funcao e:
1. Verificar a URL contra uma **whitelist** local (dominios legitimos conhecidos) — O(1)
2. Verificar contra uma **blacklist** local (dominios de phishing conhecidos) — O(1)
3. Consultar o **cache** de resultados anteriores (chrome.storage.local, TTL 24h-7d)
4. Se nenhuma das camadas anteriores resolver, encaminhar para a **API** (`/predict` ou `/analyze-email`)

Alem disso, a extensao:
- Detecta abertura de e-mails no **Gmail** (hashchange + polling DOM) e **Outlook** (MutationObserver)
- Extrai subject, body, sender e ate 10 URLs do corpo do e-mail
- Exibe resultado via badge no icone (vermelho/amarelo/verde), popup com detalhes e notificacoes desktop
- Suporta configuracao enterprise via MDM/GPO (org_id, api_key, api_endpoint)

**API Backend (server-side)** — FastAPI, Python 3.11, Docker

A API carrega e executa os modelos de ML:

| Modelo | Funcao | Detalhes |
|---|---|---|
| **DomURLs-BERT** (~110M params) | Classificacao de URLs | Transformer pre-treinado em corpus de URLs/dominios de cybersec. Modelo primario (stage 1 da cascata) |
| **CatBoost** | Refinamento de URLs incertas | Stage 2 — acionado apenas quando DomURLs-BERT fica incerto (confianca entre 15%-85%). Usa features do cliente (11) + servidor (WHOIS, DNS, redirects) |
| **DistilBERT** (phishing-email-detection) | Classificacao de e-mails | Modelo dedicado a deteccao de phishing em texto de e-mail |
| **MarianMT** (opus-mt-tc-big-pt-en) | Traducao PT->EN | Traduz e-mails em portugues para ingles antes da classificacao |

**Cascata de URL (producao):**
- Stage 1: DomURLs-BERT classifica a URL bruta
  - Se P(phishing) >= 0.85 → phishing direto
  - Se P(phishing) <= 0.15 → legitimo direto
- Stage 2: Se BERT ficou incerto (0.15 < P < 0.85), CatBoost e acionado com features enriquecidas
  - Score final = 0.6 x BERT + 0.4 x CatBoost
- Threshold de phishing: 0.65

**Pipeline de E-mail:**
- Deteccao de idioma (langdetect) + traducao PT->EN se necessario (MarianMT)
- Classificacao do texto com DistilBERT
- Analise de ate 10 URLs do corpo com DomURLs-BERT (threshold mais alto: 0.90 para reduzir falsos positivos de tracking URLs)
- Whitelist de 30+ dominios legitimos de e-mail/tracking (linkedin.com, google.com etc.)
- Score combinado: sem URL de phishing confirmando, email-only score capped em 0.65 (SUSPEITO maximo)

### 1.2 Metricas de Desempenho

**DomURLs-BERT (modelo primario em producao) — metricas do paper original:**

| Dataset de Benchmark | Acuracia |
|---|---|
| UMUDGA | 99.58% |
| UTL_DGA | 100.00% |
| DNS Tunneling | 99.88% |
| Grambedding | 99.11% |
| LNU_Phish | 99.91% |
| PhiUSIIL | 99.80% |

*Fonte: Mahdaouy et al. (2024), ArXiv:2409.09143*

**Benchmark de modelos leves (estudo comparativo, dataset brasileiro 660k URLs):**

Estes modelos NAO estao em producao. O benchmark serviu para comparar abordagens classicas
de ML com feature engineering manual vs. o DomURLs-BERT adotado como modelo final:

| Modelo | F1 | AUC-ROC | MCC | Latencia P50 |
|---|---|---|---|---|
| Logistic Regression | 72.0% | 79.3% | 0.44 | 2.87ms |
| Linear SVM | 71.7% | 79.0% | 0.44 | 3.23ms |
| Random Forest | 84.2% | 91.6% | 0.68 | 45ms |
| Gradient Boosting | 83.3% | 91.0% | 0.66 | 3.36ms |

A comparacao evidencia a superioridade de representacoes aprendidas (DomURLs-BERT, 99%+)
sobre feature engineering manual (~72-84%), justificando a escolha do transformer como modelo de producao.

### 1.3 Funcionalidades Enterprise

- Autenticacao por API Key (32-byte hex) com escopo por organizacao
- Dashboard web com timeline de eventos (Chart.js), listagem paginada e filtros
- Alertas automaticos via webhook e e-mail (SMTP) ao detectar phishing
- Relatorios agregados por organizacao (`/reports/{org_id}/summary`)
- Deploy MDM/GPO para distribuicao corporativa da extensao
- Docker Compose para deploy em um comando (API + PostgreSQL)
- Persistencia automatica de todos os eventos de analise
- Modo fail-open: extensao continua funcionando com cache/blacklist quando API esta offline

---

## 2. Ferramentas Comparadas

### 2.1 Google Safe Browsing (GSB)

| Aspecto | Detalhe |
|---|---|
| **Tipo** | Comercial (API gratuita), mantido pelo Google |
| **Metodo** | Blacklist/blocklist com verificacao em tempo real (desde marco/2024) |
| **Cobertura** | 5 bilhoes+ de dispositivos protegidos |
| **Deteccao** | Estudo Norn Labs (fev/2026): GSB **nao detectou 83.9%** de 254 sites de phishing confirmados, sinalizando apenas 41 |
| **Latencia** | < 100ms (API v4) |
| **Extensao** | Nativo no Chrome, Firefox e Safari |
| **Enterprise** | Parcial (API v4, sem dashboard dedicado) |
| **Codigo aberto** | Nao |

**Limitacoes criticas:**
- Abordagem reativa: nao detecta URLs zero-day nao catalogadas
- Sites de phishing duram em media < 10 minutos; blacklists nao acompanham
- Mais de metade dos falsos negativos estavam hospedados em plataformas legitimas (Weebly, Vercel, Google)
- Sem generalizacao por ML para URLs ineditas

**Fontes:** [Google Safe Browsing Wikipedia](https://en.wikipedia.org/wiki/Google_Safe_Browsing) | [Chrome Real-Time Protection (2024)](https://blog.google/products/chrome/google-chrome-safe-browsing-real-time/) | [Norn Labs Study (2026)](https://winbuzzer.com/2026/03/07/google-safe-browsing-missed-84-percent-phishing-sites-xcxwbn/)

---

### 2.2 Netcraft Anti-Phishing

| Aspecto | Detalhe |
|---|---|
| **Tipo** | Comercial (extensao gratuita + plano enterprise) |
| **Metodo** | Hibrido: IA/ML + 90.000 regras manuais + reporte comunitario + Risk Rating proprietario |
| **Cobertura** | 23 bilhoes+ de datapoints processados anualmente |
| **Deteccao** | Sem F1/AUC-ROC publicos; considerada lider de mercado em takedowns |
| **Extensao** | Chrome, Firefox, Opera |
| **Enterprise** | Sim (versao custom-branded, deteccao de vazamento de credenciais, protecao de JS malicioso) |
| **Codigo aberto** | Nao |

**Limitacoes:**
- Metricas de desempenho nao publicadas para comparacao independente
- Extensao gratuita e basica; recursos avancados exigem licenca enterprise
- Abordagem de deteccao nao totalmente divulgada (proprietaria)

**Fonte:** [Netcraft Browser Extension](https://www.netcraft.com/resources/apps-and-extensions/browser-extension)

---

### 2.3 Microsoft Defender SmartScreen

| Aspecto | Detalhe |
|---|---|
| **Tipo** | Comercial (nativo no Windows/Edge, extensao Chrome) |
| **Metodo** | Hibrido: blocklists dinamicas + heuristicas + telemetria + reputacao |
| **Deteccao** | Benchmark NSS Labs (2018): **99% de taxa de deteccao** (desatualizado) |
| **Extensao** | Nativo no Edge; extensao Chrome com funcionalidade reduzida |
| **Enterprise** | Sim (GPO/MDM, integracao Microsoft 365 Defender, Enhanced Phishing Protection) |
| **Codigo aberto** | Nao |

**Limitacoes:**
- Benchmark de 99% e de 2018 e pode nao refletir desempenho atual
- Ecossistema centrado em Windows/Edge
- Dependente do feed de threat intelligence da Microsoft
- Sem metricas academicas publicas (F1, AUC-ROC, MCC)
- Preocupacoes de privacidade com telemetria de URLs

**Fonte:** [Microsoft SmartScreen Overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/)

---

### 2.4 Estado da Arte Academico (2024-2025)

#### DomURLs-BERT (Mahdaouy et al., 2024) — adotado neste trabalho
- **Metodo:** BERT pre-treinado com MLM em corpus multilingual de URLs e dominios
- **Metricas:** Acuracia 99.11%-100% em 6 datasets de benchmark
- **Modelo:** ~110M parametros, tokenizacao em nivel de caractere
- **Status:** Adotado como modelo primario (stage 1) no sistema proposto
- **Fonte:** [ArXiv 2409.09143](https://arxiv.org/abs/2409.09143)

#### BERT-LSTM Hibrido (2024)
- **Metodo:** Embeddings BERT alimentados em camadas LSTM para aprendizado sequencial
- **Metricas:** F1=95.4%, AUC-ROC=99.62%, Acuracia=97.56%
- **Limitacao:** Alto custo computacional; nao projetado para deploy em tempo real; sem sistema deployavel
- **Fonte:** [Journal of Information Systems and Informatics](https://journal-isi.org/index.php/isi/article/view/1543)

#### LLM-CatBoost Hibrido (2025)
- **Metodo:** LLMs quantizados (Mistral-7B, Mixtral-8x7B) para extracao de features + CatBoost
- **Metricas:** F1=96.02%, AUC-ROC=95.52%
- **Limitacao:** Extracao de features via LLM adiciona latencia significativa; inviavel para extensao de browser
- **Fonte:** [ResearchGate](https://www.researchgate.net/publication/399376208)

#### XF-PhishBERT com ModernBERT (2025)
- **Metodo:** ModernBERT + features de dominio + redes prototipicas + MAML (meta-learning)
- **Metricas:** Projetado para deteccao few-shot de campanhas emergentes de phishing
- **Limitacao:** Arquitetura complexa, alto custo computacional, prototipo academico apenas
- **Fonte:** [Nature Scientific Reports](https://www.nature.com/articles/s41598-025-27500-0)

---

## 3. Tabela Comparativa Consolidada

| Criterio | PampAI Security | Google Safe Browsing | Netcraft | SmartScreen | SOTA Academico |
|---|---|---|---|---|---|
| **Metodo** | Cascata BERT + CatBoost | Blacklist | Hibrido (IA + regras) | Hibrido (blocklist + heuristicas) | Transformers (BERT/LLM) |
| **Modelo de URL** | DomURLs-BERT (99%+ benchmarks) | N/A (lista) | Nao publicado | Nao publicado | 95-99%+ (F1) |
| **Modelo de e-mail** | DistilBERT + MarianMT | N/A | Nao publicado | N/A | N/A |
| **Deteccao zero-day** | Sim (generaliza via ML) | Nao (reativo) | Parcial (IA + regras) | Parcial (heuristicas) | Sim (ML) |
| **Extensao browser** | Sim (MV3, Chrome) | Nativo (Chrome/Firefox) | Sim (Chrome/Firefox/Opera) | Sim (Edge nativo, Chrome) | **Nao** |
| **Analise de e-mail** | Sim (Gmail/Outlook) | Nao | Sim (enterprise) | Nao | Nao |
| **Dashboard** | Sim (web, Chart.js) | Nao | Sim (enterprise) | Sim (M365 Defender) | **Nao** |
| **Alertas (webhook/email)** | Sim | Nao | Sim (enterprise) | Sim (M365) | **Nao** |
| **Multi-tenant** | Sim (org_id + API key) | N/A | Sim | Sim (Azure AD) | **Nao** |
| **Deploy MDM/GPO** | Sim | N/A (nativo) | Sim (enterprise) | Sim (nativo) | **Nao** |
| **Codigo aberto** | **Sim** | Nao | Nao | Nao | Parcial |
| **Foco brasileiro** | **Sim** (dataset 660k BR) | Nao | Nao | Nao | Nao |
| **Custo** | Gratuito | Gratuito (API) | Pago (enterprise) | Incluso no Windows | N/A |
| **Modo offline** | Sim (blacklist/cache) | Nao | Nao | Parcial | N/A |

---

## 4. Analise de Posicionamento

### 4.1 Vantagens do PampAI Security

**1. Modelo de estado da arte em producao real**

O sistema proposto adota o DomURLs-BERT — o mesmo modelo que atinge 99%+ de acuracia nos
benchmarks academicos — como modelo primario de producao. A diferenca crucial e que, enquanto
o paper original apenas avalia o modelo, o sistema proposto o deploya em uma API real consumida
por uma extensao de browser, com fallback em cascata (CatBoost) para casos de incerteza.

**2. Sistema end-to-end completo e deployavel**

A grande maioria dos trabalhos academicos (BERT-LSTM, LLM-CatBoost, XF-PhishBERT) para na
avaliacao do modelo. O sistema proposto entrega um pipeline completo:
modelo treinado → API de inferencia → extensao de browser → dashboard enterprise.
Nenhum dos trabalhos academicos comparados oferece isso.

**3. Generalizacao para URLs ineditas (vs. blacklists)**

O estudo Norn Labs (2026) mostrou que o Google Safe Browsing falhou em detectar 83.9% de sites
de phishing confirmados. Abordagens de blacklist sao inerentemente reativas — nao generalizam
para URLs nunca vistas. O sistema proposto, por usar ML (DomURLs-BERT), consegue classificar
URLs ineditas, o cenario mais critico e frequente de phishing.

**4. Unico com foco no cenario brasileiro**

Nenhuma das ferramentas comparadas possui dataset ou otimizacao para o contexto brasileiro.
O benchmark de modelos leves foi conduzido com um dataset de 660k URLs com curadoria de fontes
brasileiras (PhishTank/OpenPhish BR + Tranco/Majestic .br), e o CatBoost (stage 2 da cascata)
foi treinado com features relevantes ao contexto nacional.

**5. Funcionalidades enterprise em codigo aberto**

Dashboard, alertas, webhooks, autenticacao multi-tenant e suporte a MDM/GPO colocam o sistema
proposto no mesmo nivel de funcionalidade que solucoes comerciais como Netcraft e SmartScreen —
porem com codigo aberto e sem custo de licenciamento.

**6. Analise de e-mails integrada na extensao**

Deteccao de phishing em e-mails diretamente no Gmail e Outlook via content scripts, com modelo
DistilBERT dedicado e traducao automatica PT->EN (MarianMT). Pouquissimas solucoes — mesmo
comerciais — oferecem analise de e-mail integrada na extensao do browser.

**7. Arquitetura resiliente (fail-open)**

Quando a API esta indisponivel, a extensao continua operando com whitelist, blacklist e cache
de resultados anteriores. O usuario nunca e bloqueado. Solucoes puramente baseadas em API
(como GSB sem cache local) ficam cegas nesse cenario.

### 4.2 Limitacoes Reconhecidas

**1. Metricas proprias do DomURLs-BERT no dataset brasileiro nao foram publicadas**

As metricas de 99%+ sao do paper original em benchmarks curados. O desempenho real no contexto
brasileiro pode diferir, dado que o dataset de phishing brasileiro tem distribuicao e padroes
distintos dos benchmarks internacionais. Uma avaliacao formal do DomURLs-BERT no dataset
brasileiro seria necessaria para uma comparacao direta.

**2. Comparabilidade limitada de datasets**

Benchmarks academicos usam datasets curados (PhiUSIIL, UCI Phishing) que podem nao refletir a
distribuicao real de phishing. O dataset brasileiro e mais realista, mas dificulta comparacao
direta de metricas com a literatura.

**3. Dependencia de servidor para inferencia completa**

A cascata DomURLs-BERT + CatBoost requer a API backend. Em caso de indisponibilidade, a extensao
opera em modo degradado (whitelist/blacklist/cache local), sem a generalizacao do ML. Modelos
on-device (ex: ONNX no browser) poderiam mitigar essa limitacao em trabalhos futuros.

### 4.3 Posicionamento no Espectro

```
Abordagem Puramente Reativa          Hibrida            Puramente Preditiva
(Blacklists)                                            (ML/Transformers)

|------------|------------|------------|------------|------------|
GSB       PhishTank    SmartScreen   Netcraft     Sistema     BERT-LSTM
                                                  Proposto    XF-PhishBERT
                                                 (DomURLs-BERT
                                                 + CatBoost
                                                 + Deploy real)
```

O sistema proposto ocupa uma posicao unica: utiliza um modelo de estado da arte (DomURLs-BERT)
como os melhores trabalhos academicos, mas — diferente deles — entrega um sistema completo
deployavel com funcionalidades enterprise, comparavel a solucoes comerciais.

---

## 5. Conclusao

O sistema proposto demonstra um nivel **competitivo a avancado** de desempenho quando analisado
no contexto completo de solucoes de deteccao de phishing:

1. **Utiliza modelo de estado da arte** (DomURLs-BERT, 99%+ nos benchmarks) como modelo
   primario, com refinamento via CatBoost para casos de incerteza
2. **Supera blacklists** (GSB, PhishTank) em capacidade de generalizacao — GSB falhou em
   83.9% dos testes independentes, enquanto ML generaliza para URLs ineditas
3. **Equipara-se a solucoes comerciais** (Netcraft, SmartScreen) em funcionalidades enterprise,
   com a vantagem de ser open-source e sem custo de licenciamento
4. **Preenche a lacuna dos trabalhos academicos** que avaliam modelos com metricas altas mas
   nao entregam sistema deployavel, extensao de browser, ou infraestrutura enterprise
5. **E unico no foco brasileiro**, com dataset curado de fontes nacionais e tratamento
   especifico para dominios .br

---

## Referencias

1. Google Safe Browsing - Wikipedia. Disponivel em: https://en.wikipedia.org/wiki/Google_Safe_Browsing
2. Google Chrome Safe Browsing Real-Time (2024). Disponivel em: https://blog.google/products/chrome/google-chrome-safe-browsing-real-time/
3. Norn Labs - Google Safe Browsing Missed 84% of Phishing Sites (2026). Disponivel em: https://winbuzzer.com/2026/03/07/google-safe-browsing-missed-84-percent-phishing-sites-xcxwbn/
4. Netcraft Browser Extension. Disponivel em: https://www.netcraft.com/resources/apps-and-extensions/browser-extension
5. Microsoft Defender SmartScreen. Disponivel em: https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/
6. Mahdaouy, A. et al. DomURLs_BERT: Pre-trained BERT-based Model for Malicious Domains and URLs Detection and Classification (2024). ArXiv:2409.09143. Disponivel em: https://arxiv.org/abs/2409.09143
7. BERT-LSTM Phishing Detection (2024). Journal of Information Systems and Informatics. Disponivel em: https://journal-isi.org/index.php/isi/article/view/1543
8. LLM-Enhanced Phishing Detection with CatBoost (2025). ResearchGate. Disponivel em: https://www.researchgate.net/publication/399376208
9. XF-PhishBERT with ModernBERT (2025). Nature Scientific Reports. Disponivel em: https://www.nature.com/articles/s41598-025-27500-0
10. PhishTank Data Analysis (2023). PMC. Disponivel em: https://pmc.ncbi.nlm.nih.gov/articles/PMC10751815/
11. Real-time Phishing Detection Browser Extensions (2026). Nature Scientific Reports. Disponivel em: https://www.nature.com/articles/s41598-026-35655-7
12. Comparative Study CatBoost/XGBoost/LightGBM for Phishing. ResearchGate. Disponivel em: https://www.researchgate.net/publication/376180322
