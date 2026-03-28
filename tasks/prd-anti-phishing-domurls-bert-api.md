# PRD: Extensao Anti-Phishing com DomURLs-BERT via API

## Introduction

A extensao Chrome anti-phishing atual usa um modelo GBM leve (ONNX, 8MB) rodando localmente no browser. O DomURLs-BERT, treinado no benchmark multimodal, apresenta metricas superiores (F1: 91.72% vs 87.27%, AUC-ROC: 97.24% vs 94.43%), mas com 422MB nao cabe na extensao. Esta PRD descreve a migracao para uma arquitetura cliente-servidor: a extensao extrai features client-side e chama uma API FastAPI dedicada que executa a inferencia com DomURLs-BERT, extrai features server-side (WHOIS, DNS), e retorna o resultado.

O deploy da API sera via **Docker container**. A API nao tera autenticacao (uso em rede local/interna). A feature `domain_google_index` sera **removida** (unreliable/rate-limited, valor fixo -1). Latencia alvo p95: **< 500ms** (DNS live ok, WHOIS cached).

## Goals

- Substituir inferencia local GBM/ONNX por chamada a API com DomURLs-BERT, aumentando F1 de 87.27% para ~91.72%
- Corrigir bug critico: formato do texto de input do modelo deve seguir o formato de treino (`[URL]...[WHOIS]...[EXTRA]...`), nao o formato atual (`URL: url | key: value`)
- Reduzir tamanho da extensao de ~95MB para ~26MB (remocao de ONNX, WASM runtime)
- Manter fail-open: extensao nunca bloqueia navegacao se API estiver offline
- Manter blacklist/whitelist locais para resposta instantanea em URLs conhecidas
- Adicionar cache local de resultados da API para minimizar chamadas repetidas
- Latencia p95 da API < 500ms (DNS live ok, WHOIS cached)

## User Stories

### US-001: Reescrever API — Request/Response e remover RF
**Description:** As a developer, I need to rewrite the FastAPI app to accept the new request format (URL + client_features) and return the new response format, removing all Random Forest / fallback logic.

**Acceptance Criteria:**
- [ ] `PhishingRequest` aceita `{ url: string, client_features: { length, dom_length, dot, hyphen, slash, at, params, shortened, tls, vowels_domain, email } }`
- [ ] `PhishingResponse` retorna `{ url, is_phishing, confidence, label, analysis, inference_ms }`
- [ ] Toda logica RF removida (`analyze_predictions`, campos RF, imports sklearn)
- [ ] Endpoint `POST /predict` funcional
- [ ] Endpoint `GET /health` retorna status do modelo, device (CPU/GPU), versao
- [ ] CORS middleware adicionado (origins configuravel, default `*`)
- [ ] Testes com pytest passam

### US-002: Corrigir formato do texto de input do modelo
**Description:** As a developer, I need to fix the `create_feature_text` function to match the training format, fixing the critical bug where the current format doesn't match what the model was trained on.

**Acceptance Criteria:**
- [ ] Texto gerado segue formato: `[URL] <url> [AGE] <dias>d [REG] <registrar> [EXPIRE] <dias>d [WHOIS] found|not_found [EXTRA] redirects=N tls=N dot=N ...`
- [ ] `max_length` do tokenizer corrigido de 512 para 128
- [ ] Quando WHOIS nao disponivel, usa `[WHOIS] not_found` e valores default para age/reg/expire
- [ ] Feature `domain_google_index` removida (valor fixo -1 ou omitida do texto)
- [ ] Teste unitario valida formato do texto gerado contra exemplos do dataset de treino

### US-003: Adicionar extracao de features server-side (WHOIS + DNS)
**Description:** As a developer, I need the API to extract server-side features (WHOIS data, DNS records, redirects) that cannot be obtained from the browser extension.

**Acceptance Criteria:**
- [ ] WHOIS lookup com cache local (`whois_cache.json`), fallback live com timeout 3s
- [ ] DNS queries: MX servers, nameservers, SPF record, A record — timeout 2s cada
- [ ] Contagem de HTTP redirects (seguir cadeia de redirects)
- [ ] Features extraidas: `redirects`, `dom_age`, `dom_expire`, `mx_servers`, `nameservers`, `dom_spf`, `dom_in_ip`, `srv_client`
- [ ] `domain_google_index` retorna -1 fixo (feature removida)
- [ ] Falha em qualquer lookup individual nao bloqueia a resposta (usa valor default -1)
- [ ] Latencia p95 total < 500ms com WHOIS em cache

### US-004: Adicionar endpoint batch
**Description:** As a developer, I need a batch prediction endpoint for efficiency when multiple URLs need analysis.

**Acceptance Criteria:**
- [ ] Endpoint `POST /predict-batch` aceita array de requests
- [ ] Retorna array de responses na mesma ordem
- [ ] Tokenizacao em batch (nao N chamadas sequenciais ao modelo)
- [ ] Teste com batch de 5 URLs funciona corretamente

### US-005: Dockerizar a API
**Description:** As a developer, I need the API deployable as a Docker container for easy deployment.

**Acceptance Criteria:**
- [ ] `Dockerfile` funcional com dependencias (torch, transformers, fastapi, whois, dnspython)
- [ ] `docker-compose.yml` com configuracao de porta e volume para modelo
- [ ] Container inicia e responde no `/health` sem erros
- [ ] Documentacao minima de como subir (`docker-compose up`)

### US-006: Criar modulo clientFeatures.ts
**Description:** As a developer, I need a new TypeScript module that extracts the 11 client-side features from a URL, replacing the old features.ts (51 features do GBM).

**Acceptance Criteria:**
- [ ] Arquivo `src/utils/clientFeatures.ts` criado
- [ ] Extrai todas 11 features: `length`, `dom_length`, `dot`, `hyphen`, `slash`, `at`, `params`, `shortened`, `tls`, `vowels_domain`, `email`
- [ ] `shortened` verifica contra lista de encurtadores conhecidos (bit.ly, tinyurl, t.co, etc.)
- [ ] `email` usa regex para detectar email na URL
- [ ] Funcao exportada: `extractClientFeatures(url: string): ClientFeatures`
- [ ] Interface `ClientFeatures` exportada com os 11 campos tipados como `number`
- [ ] Typecheck passa

### US-007: Criar modulo api.ts (cliente HTTP)
**Description:** As a developer, I need an API client module for the extension to communicate with the FastAPI backend.

**Acceptance Criteria:**
- [ ] Arquivo `src/utils/api.ts` criado
- [ ] Funcao `analyzeUrl(url: string, features: ClientFeatures): Promise<ApiResponse>` exportada
- [ ] Funcao `checkHealth(): Promise<HealthResponse>` exportada
- [ ] Timeout de 5 segundos em todas as chamadas
- [ ] URL da API configuravel via `chrome.storage.sync` (default: `http://localhost:8000`)
- [ ] Erros de rede retornam `{ offline: true }` em vez de throw
- [ ] Typecheck passa

### US-008: Criar modulo cache.ts
**Description:** As a developer, I need a URL analysis cache to avoid repeated API calls for frequently visited URLs.

**Acceptance Criteria:**
- [ ] Arquivo `src/utils/cache.ts` criado
- [ ] Interface `CacheEntry`: `{ isPhishing, confidence, label, analysis, timestamp }`
- [ ] Storage: `chrome.storage.local` sob chave `"urlCache"`
- [ ] Chave de lookup: URL normalizada (lowercase hostname, sem trailing slash)
- [ ] TTL: 24h para LEGITIMO, 7 dias para PHISHING
- [ ] Limite: 5000 entradas; quando excede, remove 20% mais antigos (LRU eviction)
- [ ] Funcoes exportadas: `getCached(url)`, `setCached(url, entry)`, `clearCache()`
- [ ] Typecheck passa

### US-009: Reescrever background.ts (orquestrador)
**Description:** As a developer, I need to rewrite the background service worker to orchestrate the analysis pipeline: whitelist -> blacklist -> cache -> API, replacing the current ONNX-based flow.

**Acceptance Criteria:**
- [ ] Pipeline de analise: whitelist (instant) -> blacklist (instant) -> cache (instant) -> API call
- [ ] Resultado armazenado por tab em `chrome.storage.session`
- [ ] Mensagens suportadas: `ANALYZE_URL`, `GET_RESULT`, `GET_API_STATUS`, `CLEAR_CACHE`, `SET_API_URL`
- [ ] `ANALYZE_URL` recebe `{ url, features }` e retorna `{ isPhishing, confidence, label, analysis, source, offline? }`
- [ ] `source` indica origem: `"blacklist"` | `"whitelist"` | `"cache"` | `"api"` | `"offline"`
- [ ] Falha na API retorna `{ offline: true }` (fail-open, nao bloqueia)
- [ ] Service Worker reinicia sem perda de cache (cache em `storage.local`, nao in-memory)
- [ ] Nenhuma referencia a ONNX, inference.ts, ou features.ts
- [ ] Typecheck passa

### US-010: Atualizar detector.ts (content script)
**Description:** As a developer, I need to update the content script to extract client features, send them to the background, and display banners based on API results (not just blacklist hits).

**Acceptance Criteria:**
- [ ] Ignora paginas internas (`chrome://`, `about://`, `edge://`)
- [ ] Extrai 11 client_features usando `clientFeatures.ts`
- [ ] Envia `{ type: "ANALYZE_URL", url, features }` ao background
- [ ] Phishing detectado (qualquer source) -> banner vermelho
- [ ] Confianca < 70% -> banner laranja (aviso)
- [ ] Legitimo -> nenhum banner
- [ ] Offline -> nenhum banner (fail-open)
- [ ] Nenhuma referencia a inference.ts ou features.ts antigos
- [ ] Typecheck passa

### US-011: Reescrever popup.tsx
**Description:** As a user, I want to see the analysis result, API status, and have controls to manage cache and API settings when I click the extension icon.

**Acceptance Criteria:**
- [ ] Remove todo carregamento de modelo ONNX
- [ ] Pega resultado do background via mensagem `GET_RESULT`
- [ ] Mostra card com: resultado (PHISHING/LEGITIMO), confianca (%), texto de analise, source
- [ ] Indicador visual de API online/offline (verifica via `GET_API_STATUS`)
- [ ] Botao "Limpar Cache" funcional (chama `CLEAR_CACHE`)
- [ ] Campo configuravel para URL da API (chama `SET_API_URL`)
- [ ] Texto indica "DomURLs-BERT via API" como motor de analise
- [ ] Typecheck passa
- [ ] Verify in browser using dev-browser skill

### US-012: Atualizar logger.ts
**Description:** As a developer, I need to update the logger to reflect the new analysis sources.

**Acceptance Criteria:**
- [ ] Campo `source` adicionado: `"blacklist"` | `"whitelist"` | `"cache"` | `"api"` | `"offline"`
- [ ] Campo `featuresUsed` removido (nao mais relevante)
- [ ] Typecheck passa

### US-013: Limpar package.json e assets
**Description:** As a developer, I need to remove ONNX/WASM dependencies and assets that are no longer needed.

**Acceptance Criteria:**
- [ ] `onnxruntime-web` removido do package.json
- [ ] `tldts` removido do package.json (se nao usado em outro lugar)
- [ ] `wasm-unsafe-eval` removido do CSP no manifest
- [ ] `web_accessible_resources` limpo (remover referencias a .onnx e .wasm)
- [ ] Arquivos deletados: `src/utils/inference.ts`, `src/utils/features.ts`
- [ ] Assets deletados: `assets/modelo/modelo_phishing_ort14.onnx`, `assets/ort*.wasm`, `assets/ort.min.js`, `assets/ort.wasm.min.js`
- [ ] `npm install` roda sem erros
- [ ] Typecheck passa

### US-014: Testes de integracao end-to-end
**Description:** As a developer, I need to verify the full pipeline works: extension <-> API with all scenarios.

**Acceptance Criteria:**
- [ ] API sobe via `docker-compose up` sem erros
- [ ] Extensao carrega no Chrome sem erros no console
- [ ] Cenario: blacklist hit -> banner vermelho instantaneo, sem chamada API
- [ ] Cenario: whitelist hit -> nenhum banner, sem chamada API
- [ ] Cenario: URL desconhecida -> chamada API, resultado correto, cacheado
- [ ] Cenario: mesma URL novamente -> resultado vem do cache, sem chamada API
- [ ] Cenario: API offline -> fail-open, popup mostra "offline"
- [ ] Cenario: API volta online -> proxima URL desconhecida usa API normalmente
- [ ] Popup mostra resultado correto para cada cenario

## Functional Requirements

- **FR-01:** A API deve expor `POST /predict` aceitando `{ url, client_features }` e retornando `{ url, is_phishing, confidence, label, analysis, inference_ms }`
- **FR-02:** A API deve expor `POST /predict-batch` aceitando array de requests e retornando array de responses
- **FR-03:** A API deve expor `GET /health` retornando status do modelo, device, e versao
- **FR-04:** A API deve formatar o texto de input no formato de treino: `[URL] <url> [AGE] <dias>d [REG] <registrar> [EXPIRE] <dias>d [WHOIS] found|not_found [EXTRA] key=value ...`
- **FR-05:** A API deve tokenizar com `max_length=128` (nao 512)
- **FR-06:** A API deve buscar WHOIS com cache local e fallback live (timeout 3s)
- **FR-07:** A API deve buscar DNS (MX, NS, SPF, A) com timeout 2s por query
- **FR-08:** A API deve contar HTTP redirects seguindo a cadeia
- **FR-09:** A API deve incluir CORS middleware (default: aceitar todas as origens)
- **FR-10:** A API deve medir e retornar `inference_ms` em cada resposta
- **FR-11:** A extensao deve extrair 11 features client-side da URL (length, dom_length, dot, hyphen, slash, at, params, shortened, tls, vowels_domain, email)
- **FR-12:** O background deve seguir o pipeline: whitelist -> blacklist -> cache -> API
- **FR-13:** O background deve cachear resultados com TTL 24h (legitimo) / 7d (phishing), max 5000 entradas
- **FR-14:** O background deve fazer LRU eviction (20% mais antigos) quando cache excede 5000 entradas
- **FR-15:** O content script deve injetar banner vermelho para phishing, banner laranja para confianca < 70%
- **FR-16:** A extensao deve fazer fail-open: nunca bloquear navegacao quando API offline
- **FR-17:** O popup deve mostrar resultado, confianca, source, status da API, e controles (limpar cache, configurar URL)
- **FR-18:** O popup deve permitir configurar a URL da API (default: `http://localhost:8000`)
- **FR-19:** O background deve armazenar resultado por tab em `chrome.storage.session`
- **FR-20:** A feature `domain_google_index` deve ser removida (valor fixo -1)

## Non-Goals

- **Nao** retreinar o modelo com features HTML (forms, iframes, scripts) — requer dataset novo
- **Nao** implementar pre-analise via `chrome.webNavigation` (otimizacao futura)
- **Nao** compactar ou particionar a blacklist (24.6MB permanece como esta)
- **Nao** implementar WHOIS cache compartilhado entre API e extensao
- **Nao** implementar rate limiting na API (rede interna, sem auth)
- **Nao** implementar autenticacao na API (deploy local/interno)
- **Nao** implementar deploy serverless ou cloud — apenas Docker local
- **Nao** analisar conteudo HTML real das paginas (modelo nao foi treinado nisso)

## Design Considerations

- O popup deve manter o estilo visual atual da extensao, apenas substituindo informacoes do modelo GBM por DomURLs-BERT
- Indicador de status API: bolinha verde (online) / vermelha (offline) no canto superior do popup
- Banner de phishing: manter estilo atual (vermelho), adicionar banner laranja para confianca baixa (< 70%)
- Campo de configuracao da URL da API: input de texto simples com botao "Salvar" no popup

## Technical Considerations

- **Modelo:** DomURLs-BERT (422MB) carregado uma vez na inicializacao da API, mantido em memoria
- **Framework API:** FastAPI + uvicorn
- **Deploy:** Docker container com `docker-compose.yml`
- **WHOIS:** Biblioteca `python-whois` com cache em JSON local
- **DNS:** Biblioteca `dnspython` para queries MX, NS, TXT/SPF, A
- **Tokenizer:** HuggingFace Transformers, `max_length=128`
- **Extensao:** Chrome MV3 com Plasmo framework (manter stack atual)
- **Cache extensao:** `chrome.storage.local` (~5MB limite no Chrome, 5000 entradas ~1MB)
- **Latencia:** p95 < 500ms com WHOIS em cache; DNS live aceitavel
- **Concorrencia:** FastAPI async; WHOIS/DNS podem ser I/O bound, considerar `asyncio.gather` para paralelizar lookups

## Success Metrics

- F1-score do modelo em producao >= 91% (vs 87.27% do GBM)
- Tamanho da extensao empacotada reduzido de ~95MB para ~26MB
- Latencia p95 da API < 500ms para URLs com WHOIS em cache
- Taxa de cache hit > 60% apos 1 semana de uso tipico
- Zero bloqueios de navegacao por falha da API (fail-open 100%)
- Extensao funciona normalmente (blacklist/whitelist) mesmo com API desligada

## Open Questions

1. Qual registrar WHOIS usar para dominios `.br`? `python-whois` tem cobertura limitada para ccTLDs
2. O modelo DomURLs-BERT atual esta salvo em formato PyTorch ou ja foi convertido para ONNX para a API? (se ONNX, podemos usar onnxruntime no servidor para inferencia mais rapida)
3. O formato exato do texto de treino precisa ser validado contra o script de treino original — ha acesso ao codigo de preprocessamento do treino?
4. A blacklist de 24.6MB impacta o tempo de carregamento da extensao — vale investigar lazy loading ou compressao em fase futura?
5. Como lidar com URLs que fazem redirect para dominios diferentes? Analisar URL original, final, ou ambas?
