# PRD: Endpoint de Analise de Email Phishing

## Introduction

Adicionar deteccao de phishing em emails a API existente e integrar com a extensao para analise em webmail (Gmail/Outlook). O sistema atual detecta phishing por URL (DomURLs-BERT + CatBoost cascata, 95.2% accuracy). Esta feature adiciona um endpoint `/analyze-email` que classifica o conteudo do email usando DistilBERT (`cybersectony/phishing-email-detection-distilbert_v2.4.1`, 66M params, 99.58% F1), com traducao automatica PT->EN via MarianMT (`Helsinki-NLP/opus-mt-tc-big-pt-en`). URLs no corpo do email sao analisadas com BERT (sem cascata CatBoost, pois nao ha client_features). Um notebook de benchmark valida o modelo para o TCC.

Refs: "Improving phishing email detection through deep learning" (Nature Scientific Reports, 2025), "In-Depth Analysis of Phishing Email Detection" (Applied Sciences, 2025).

## Goals

- Classificar emails como PHISHING (>60%) / SUSPICIOUS (40-60%) / LEGITIMO (<40%) via DistilBERT com F1 >= 95% em ingles
- Traduzir emails em portugues para ingles antes da classificacao (MarianMT)
- Analisar URLs no corpo do email usando BERT (sem cascata)
- Combinar score do email + scores das URLs em decisao final ponderada
- Detectar e extrair emails automaticamente em Gmail e Outlook via content script
- Gerar benchmark com metricas (accuracy, F1, precision, recall, AUC-ROC) para o TCC

## User Stories

### US-001: Pydantic models para email
**Description:** As a developer, I need request/response models for the email analysis endpoint so the API has typed, validated input/output.

**Acceptance Criteria:**
- [ ] `EmailRequest(BaseModel)` com campos: `subject: str = ""`, `body: str = ""`, `sender: str = ""`, `urls_in_body: List[str] = []`
- [ ] `EmailUrlResult(BaseModel)` com campos: `url: str`, `is_phishing: bool`, `confidence: float`, `label: str`
- [ ] `EmailResponse(BaseModel)` com campos: `is_phishing: bool`, `confidence: float`, `label: str` (PHISHING / SUSPICIOUS / LEGITIMO), `analysis: str`, `inference_ms: float`, `email_score: float`, `url_results: List[EmailUrlResult]`, `language_detected: str`, `translated: bool`
- [ ] Models definidos em `phishing-api/app.py` junto com os models existentes
- [ ] Typecheck/lint passa

### US-002: Carregar modelos de email e traducao no startup
**Description:** As a developer, I need the DistilBERT email model and MarianMT translation model loaded on API startup so they're ready for inference.

**Acceptance Criteria:**
- [ ] Variaveis globais: `email_model`, `email_tokenizer`, `translation_model`, `translation_tokenizer` (iniciam `None`)
- [ ] Constantes: `EMAIL_MODEL_ID = "cybersectony/phishing-email-detection-distilbert_v2.4.1"`, `TRANSLATION_MODEL_ID = "Helsinki-NLP/opus-mt-tc-big-pt-en"`
- [ ] `load_model()` carrega DistilBERT email (`AutoTokenizer` + `AutoModelForSequenceClassification`) apos BERT URL e CatBoost existentes
- [ ] `load_model()` carrega MarianMT (`MarianTokenizer` + `MarianMTModel`) para traducao PT->EN
- [ ] Ambos modelos enviados para `device` e colocados em `.eval()`
- [ ] Log de sucesso ao carregar cada modelo
- [ ] API inicia sem erro com os novos modelos

### US-003: Funcao de deteccao de idioma e traducao
**Description:** As a developer, I need a function to detect the email language and translate PT->EN so the DistilBERT model (English-only) can classify Portuguese emails.

**Acceptance Criteria:**
- [ ] Funcao `detect_and_translate(text: str) -> tuple[str, str, bool]` retorna `(texto_en, idioma_detectado, foi_traduzido)`
- [ ] Usa `langdetect.detect()` para deteccao de idioma
- [ ] Se idioma == "pt" e `translation_model` disponivel, traduz com MarianMT (truncation=True, max_length=512)
- [ ] Se idioma != "pt", retorna texto original sem traducao
- [ ] Inferencia com `torch.no_grad()` para eficiencia
- [ ] `langdetect>=1.0.9` adicionado ao `requirements.txt`

### US-004: Funcao de analise de URLs do email
**Description:** As a developer, I need a function to analyze URLs found in the email body using only BERT (no cascade) since client_features aren't available for email URLs.

**Acceptance Criteria:**
- [ ] Funcao `_analyze_email_urls(urls: List[str]) -> List[EmailUrlResult]`
- [ ] Usa `_bert_predict(url)` diretamente (sem cascata CatBoost)
- [ ] Limita a 10 URLs por email (`urls[:10]`)
- [ ] Para cada URL: calcula `is_phishing` (prob > `PHISHING_THRESHOLD`), confidence (0-100), label ("PHISHING"/"LEGITIMO")
- [ ] Retorna lista de `EmailUrlResult`

### US-005: Endpoint POST /analyze-email
**Description:** As a developer, I need the main email analysis endpoint that combines email content classification with URL analysis for a final phishing decision.

**Acceptance Criteria:**
- [ ] `POST /analyze-email` com `response_model=EmailResponse`
- [ ] Retorna HTTP 503 se `email_model is None`
- [ ] Constantes: `EMAIL_PHISHING_THRESHOLD = 0.6`, `EMAIL_SUSPICIOUS_THRESHOLD = 0.4`, `EMAIL_WEIGHT = 0.6`
- [ ] Pipeline: (1) concatena subject + body, (2) `detect_and_translate()`, (3) tokeniza e classifica com DistilBERT email, (4) `_analyze_email_urls()` nas URLs do body
- [ ] Combinacao de scores: se qualquer URL phishing com confidence > 80% -> `final_prob = max(email_prob, 0.9)`; se tem URLs phishing -> media ponderada (60% email, 40% max URL); senao -> so email_prob
- [ ] Labels: `final_prob > 0.6` -> PHISHING, `0.4 <= final_prob <= 0.6` -> SUSPICIOUS, `final_prob < 0.4` -> LEGITIMO
- [ ] `is_phishing = final_prob > EMAIL_PHISHING_THRESHOLD` (true apenas para PHISHING, false para SUSPICIOUS e LEGITIMO)
- [ ] Confidence calculada: `(final_prob if is_phishing else 1.0 - final_prob) * 100`
- [ ] Funcao `_build_email_analysis()` gera texto de analise legivel
- [ ] `inference_ms` medido com `time.perf_counter()`
- [ ] Resposta inclui todos os campos de `EmailResponse`

### US-006: Health check atualizado
**Description:** As a developer, I need the health endpoint to report email model status so monitoring can verify the new model is loaded.

**Acceptance Criteria:**
- [ ] `/health` retorna campo adicional `email_model_loaded: bool` (= `email_model is not None`)
- [ ] `API_VERSION` bumped para `"4.0.0"`
- [ ] Campos existentes (`status`, `model_loaded`, `cascade_enabled`, `device`, `version`) mantidos

### US-007: Testes unitarios do endpoint de email
**Description:** As a developer, I need tests for the email analysis endpoint to validate correct behavior with different inputs.

**Acceptance Criteria:**
- [ ] Teste com email phishing em ingles -> `is_phishing: true`, `label: "PHISHING"`
- [ ] Teste com email legitimo -> `is_phishing: false`, `label: "LEGITIMO"`
- [ ] Teste com email ambiguo -> `label: "SUSPICIOUS"` (score entre 40-60%)
- [ ] Teste com email em portugues -> `translated: true`, `language_detected: "pt"`
- [ ] Teste com URLs no body -> `url_results` preenchido
- [ ] Teste com body vazio -> resposta valida (sem erro)
- [ ] Teste do `/health` -> `email_model_loaded: true`
- [ ] Testes adicionados em `phishing-api/test_api.py`

### US-008: Atualizar Dockerfile
**Description:** As a developer, I need the Dockerfile to pre-download email and translation models so container startup is fast.

**Acceptance Criteria:**
- [ ] Adicionar step `RUN python -c "..."` que pre-baixa os 4 artefatos: `AutoTokenizer` + `AutoModelForSequenceClassification` do EMAIL_MODEL_ID, `MarianTokenizer` + `MarianMTModel` do TRANSLATION_MODEL_ID
- [ ] Step adicionado apos `pip install` e antes do `COPY` do codigo
- [ ] Docker build completa sem erro
- [ ] `docker-compose up` -> `/health` retorna `email_model_loaded: true`

### US-009: Interface EmailAnalysisResponse no api.ts
**Description:** As a developer, I need the TypeScript interface and API function for email analysis so the extension can call the new endpoint.

**Acceptance Criteria:**
- [ ] Interface `EmailAnalysisResponse` em `extensao-phishing/src/utils/api.ts` com todos os campos: `is_phishing`, `confidence`, `label`, `analysis`, `inference_ms`, `email_score`, `url_results[]`, `language_detected`, `translated`
- [ ] Funcao `analyzeEmail(email: { subject, body, sender, urls_in_body })` que faz POST para `/analyze-email`
- [ ] Usa mesma estrutura de `fetchWithTimeout` que `analyzeUrl`
- [ ] Retorna `EmailAnalysisResponse | ApiOfflineResponse`
- [ ] Typecheck passa

### US-010: Content script webmail-detector.ts
**Description:** As a user, I want the extension to automatically detect when I'm reading an email in Gmail or Outlook so the email content is analyzed for phishing.

**Acceptance Criteria:**
- [ ] Novo arquivo `extensao-phishing/src/contents/webmail-detector.ts`
- [ ] PlasmoCSConfig com matches: `*://mail.google.com/*`, `*://outlook.live.com/*`, `*://outlook.office365.com/*`, `*://outlook.office.com/*`
- [ ] `run_at: "document_idle"`
- [ ] Extrai do DOM Gmail: hierarquia de seletores — primeiro especificos (`h2.hP`, `div.a3s.aiL`, `span.gD[email]`), fallback para semanticos (`[role="main"]`, `[data-message-id]`, `[aria-label]`)
- [ ] Extrai do DOM Outlook: seletores semanticos (`div[role="document"]`, `[role="main"]`), mais estaveis que classes CSS
- [ ] Se nenhum seletor funcionar, falha silenciosamente (nao analisa, nao quebra o webmail)
- [ ] `MutationObserver` no `document.body` para detectar navegacao SPA (abrir/fechar emails)
- [ ] Debounce de 500ms para evitar analises duplicadas
- [ ] Hash do ultimo email analisado para evitar re-analise
- [ ] Envia `chrome.runtime.sendMessage({ type: "ANALYZE_EMAIL", email: { subject, body, sender, urls_in_body } })`
- [ ] Typecheck passa

### US-011: Handler ANALYZE_EMAIL no background.ts
**Description:** As a developer, I need the background script to handle email analysis messages from the webmail content script.

**Acceptance Criteria:**
- [ ] Novo handler para `message.type === "ANALYZE_EMAIL"` no listener `onMessage` em `extensao-phishing/src/background.ts`
- [ ] Chama `analyzeEmail(message.email)` do `api.ts`
- [ ] Armazena resultado via `storeTabResult(tabId, { ...result, url: "email:" + message.email.sender })`
- [ ] Atualiza badge via `updateBadge(tabId, result)`
- [ ] Emite notificacao se phishing detectado
- [ ] `sendResponse({ success: true, result })` no sucesso
- [ ] Tratamento de erro no `.catch()`
- [ ] `return true` para manter canal de mensagem aberto (async)

### US-012: Popup com visualizacao de resultado de email
**Description:** As a user, I want to see email analysis results in the popup when viewing a webmail message so I know if the email is phishing.

**Acceptance Criteria:**
- [ ] Detecta resultado de email via `result.url.startsWith("email:")`
- [ ] Mostra "Analise de Email" como titulo em vez do card de URL
- [ ] Mostra sender no lugar da URL
- [ ] Card com 3 estados: PHISHING (vermelho), SUSPICIOUS (amarelo/laranja), LEGITIMO (verde)
- [ ] Secao "URLs no email" listando cada `url_result` com cor (vermelho phishing, verde legitimo)
- [ ] Indicador de idioma detectado (ex: "Idioma: pt") e se foi traduzido (ex: "Traduzido para EN")
- [ ] Mantem ConfidenceBar e metricas existentes
- [ ] Typecheck passa

### US-013: Notebook de benchmark do modelo de email
**Description:** As a researcher, I need a benchmark notebook to validate the email phishing model and generate metrics/graphs for the TCC.

**Acceptance Criteria:**
- [ ] Novo notebook `benchmark-modelos/benchmark_email_phishing.ipynb` (compativel com Google Colab T4)
- [ ] Celula 1: Setup — instalar transformers, langdetect, datasets, sklearn, matplotlib
- [ ] Celula 2: Carregar dataset `cybersectony/PhishingEmailDetectionv2.0` do HuggingFace
- [ ] Celula 3: Avaliar `cybersectony/phishing-email-detection-distilbert_v2.4.1` (baseline)
- [ ] Celula 4: Avaliar alternativa multilingual (XLM-R ou similar) para comparacao
- [ ] Celula 5: Testar traducao PT->EN com MarianMT em amostra manual de emails em portugues
- [ ] Celula 6: Metricas — accuracy, F1, precision, recall, AUC-ROC, confusion matrix
- [ ] Celula 7: Comparacao de latencia (DistilBERT vs alternativa)
- [ ] Celula 8: Gerar graficos (matplotlib) e tabelas para o TCC, salvar em `benchmark-modelos/resultados/`

### US-014: Teste de integracao end-to-end do fluxo de email
**Description:** As a developer, I need integration tests that validate the full email analysis flow from API request to response.

**Acceptance Criteria:**
- [ ] Teste com curl: POST `/analyze-email` com email phishing em ingles -> resposta com `is_phishing: true`, `email_score > 50`
- [ ] Teste com curl: POST `/analyze-email` com email em portugues -> `translated: true`, `language_detected: "pt"`
- [ ] Teste com curl: POST `/analyze-email` com `urls_in_body` contendo URL phishing -> `url_results` preenchido
- [ ] Teste do `/health` -> `email_model_loaded: true`, `version: "4.0.0"`
- [ ] Testes adicionados em `phishing-api/test_integration.py`

## Functional Requirements

- FR-1: O sistema deve aceitar `POST /analyze-email` com body JSON contendo `subject`, `body`, `sender`, `urls_in_body`
- FR-2: O sistema deve detectar o idioma do email usando `langdetect`
- FR-3: Se o idioma detectado for "pt", o sistema deve traduzir o texto para ingles usando MarianMT antes da classificacao
- FR-4: O sistema deve classificar o email (subject + body) como PHISHING (>60%) / SUSPICIOUS (40-60%) / LEGITIMO (<40%) usando DistilBERT `cybersectony/phishing-email-detection-distilbert_v2.4.1`
- FR-5: O sistema deve analisar cada URL no corpo do email usando `_bert_predict()` (sem cascata CatBoost)
- FR-6: O sistema deve limitar a analise a no maximo 10 URLs por email
- FR-7: O sistema deve combinar o score do email com os scores das URLs: peso 60% email / 40% max URL phishing; se qualquer URL phishing > 80% confidence, boost para `max(email_prob, 0.9)`
- FR-8: O sistema deve retornar resposta com todos os campos de `EmailResponse` incluindo `email_score`, `url_results[]`, `language_detected`, `translated`
- FR-9: O endpoint `/health` deve reportar `email_model_loaded` e version `4.0.0`
- FR-10: O Dockerfile deve pre-baixar os modelos DistilBERT email e MarianMT no build
- FR-11: A extensao deve detectar automaticamente quando o usuario esta lendo um email em Gmail ou Outlook
- FR-12: A extensao deve extrair subject, body (texto limpo), sender e URLs do DOM do webmail
- FR-13: A extensao deve enviar os dados do email para o background via `chrome.runtime.sendMessage` com type `ANALYZE_EMAIL`
- FR-14: O background deve chamar `analyzeEmail()` da API e atualizar badge/popup com o resultado
- FR-15: O popup deve exibir resultado de analise de email com sender, score, URLs analisadas, idioma detectado e status de traducao
- FR-16: O notebook de benchmark deve gerar metricas (accuracy, F1, precision, recall, AUC-ROC) e graficos para o TCC

## Non-Goals

- Analise de anexos (PDF, imagens, etc.) — apenas texto do email
- Fine-tuning do modelo DistilBERT — usar pre-treinado do HuggingFace
- Traducao de idiomas alem de portugues — apenas PT->EN
- Cascata CatBoost para URLs do email — sem client_features disponiveis
- Deteccao em clientes de email desktop (Thunderbird, Apple Mail, etc.)
- Armazenamento ou logging do conteudo dos emails
- Suporte a Yahoo Mail ou outros webmail alem de Gmail/Outlook
- Rate limiting no endpoint `/analyze-email` (API roda local, so a extensao consome)
- Sliding window para emails longos (truncation simples e suficiente para TCC)

## Technical Considerations

- **Modelo de email:** DistilBERT 66M params, rapido para CPU/GPU. Truncation em 512 tokens (suficiente para subject + body)
- **Traducao:** MarianMT ~300MB, mesma interface transformers, roda em GPU. Alternativa descartada: argostranslate (requer language packs externos)
- **Memoria:** +2 modelos na GPU/RAM. DistilBERT ~250MB + MarianMT ~300MB = ~550MB adicional
- **Latencia:** DistilBERT ~50-100ms (GPU) / ~200-500ms (CPU). MarianMT adiciona ~100-300ms para traducao. Total estimado: 150-800ms
- **DOM extraction:** Seletores do Gmail sao ofuscados e podem mudar. Estrategia: hierarquia de seletores — especificos primeiro, fallback para semanticos (`[role]`, `[data-*]`, `[aria-label]`). Se nenhum funcionar, falha silenciosa. Outlook usa atributos semanticos mais estaveis. MutationObserver necessario para SPA navigation
- **Truncation:** Emails > 512 tokens sao truncados (padrao dos papers). Emails phishing colocam conteudo urgente no inicio. Format `Subject: ...\n\nbody` prioriza subject
- **Dependencias:** Apenas `langdetect>=1.0.9` novo. MarianMT ja esta no `transformers`
- **Compatibilidade:** Manter todos os endpoints existentes (`/predict`, `/predict-batch`, `/health`) funcionando sem alteracao

## Success Metrics

- Endpoint `/analyze-email` responde com classificacao correta para emails phishing conhecidos
- F1 >= 95% no benchmark com dataset `cybersectony/PhishingEmailDetectionv2.0`
- Traducao PT->EN preserva contexto suficiente para classificacao correta (validar com amostra manual)
- Latencia < 1s para email sem URLs, < 2s para email com 10 URLs
- Content script detecta abertura de email em Gmail e Outlook e envia dados corretamente
- Popup exibe resultado de email com todas as informacoes relevantes
- Docker build e startup sem erros com os novos modelos

## Resolved Questions

- **Label SUSPICIOUS:** Sim — PHISHING (>60%), SUSPICIOUS (40-60%), LEGITIMO (<40%). Email e mais ambiguo que URL, tres labels dao informacao mais util ao usuario
- **Rate limiting:** Nao agora. API roda local (Docker), so a extensao consome. Adicionar se expor publicamente no futuro
- **Emails > 512 tokens:** Truncation simples e suficiente. Emails phishing colocam conteudo urgente no inicio (subject + primeiros paragrafos). Padrao dos papers de referencia
- **Seletores do Gmail:** Hierarquia de seletores — especificos primeiro (`h2.hP`, `div.a3s.aiL`), fallback para semanticos (`[role="main"]`, `[data-message-id]`, `aria-label`). Gmail tem `data-*` e `role` mais estaveis que classes CSS. Se nenhum funcionar, falha silenciosa (nao analisa, nao quebra webmail). Outlook usa atributos semanticos mais estaveis

## Open Questions

- Nenhuma questao pendente
