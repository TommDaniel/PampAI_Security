# Analise da Branch `ralph/email-phishing-analysis`

**Data:** 2026-04-04
**Branch:** `ralph/email-phishing-analysis`
**Base:** `main`
**Escopo:** Deteccao de phishing em emails (API + Extensao Chrome)

---

## 1. Resumo

Esta branch implementa a funcionalidade completa de **analise de phishing em emails** no sistema, abrangendo backend (API FastAPI) e frontend (extensao Chrome MV3). Sao **14 user stories** (US-001 a US-014) totalizando ~4.000 linhas adicionadas em 10 arquivos.

### Commits da branch

| Commit | US | Descricao |
|--------|----|-----------|
| `1e03f97` | US-001 | Pydantic models para email |
| `5672a6f` | US-002 | Carregar modelos de email e traducao no startup |
| `a262704` | US-003 | Funcao de deteccao de idioma e traducao |
| `233b0ba` | US-004 | Funcao de analise de URLs do email |
| `90e88ad` | US-005 | Endpoint POST /analyze-email |
| `d1b4ba8` | US-006 | Health check atualizado |
| `8bd6d58` | US-007 | Testes unitarios do endpoint de email |
| `4780185` | US-008 | Atualizar Dockerfile |
| `78d52b1` | US-009 | Interface EmailAnalysisResponse no api.ts |
| `b0f4693` | US-010 | Content script webmail-detector.ts |
| `73c9c35` | US-011 | Handler ANALYZE_EMAIL no background.ts |
| `5ea6d58` | US-012 | Popup com visualizacao de resultado de email |
| `62e1c37` | US-013 | Notebook de benchmark do modelo de email |
| `01ee6fe` | US-014 | Teste de integracao end-to-end do fluxo de email |

---

## 2. API (`phishing-api/`)

### 2.1 Novos modelos de ML carregados

| Modelo | ID | Papel |
|--------|----|-------|
| **DistilBERT Email** | `cybersectony/phishing-email-detection-distilbert_v2.4.1` | Classifica o conteudo textual do email (phishing/legitimo) |
| **MarianMT** | `Helsinki-NLP/opus-mt-tc-big-pt-en` | Traduz emails em portugues para ingles antes da analise |

Ambos sao carregados no startup da API (`app.py`). O MarianMT e opcional — se nao conseguir baixar, a API continua funcionando sem traducao.

### 2.2 Novo endpoint: `POST /analyze-email`

**Request:**
```json
{
  "subject": "Atualize sua conta",
  "body": "Clique no link para verificar...",
  "sender": "seguranca@banco-falso.com",
  "urls_in_body": ["https://banco-falso.com/login"]
}
```

**Response:**
```json
{
  "is_phishing": true,
  "confidence": 87.5,
  "label": "PHISHING",
  "analysis": "Email classificado como phishing...",
  "inference_ms": 45.2,
  "email_score": 0.82,
  "url_results": [
    {
      "url": "https://banco-falso.com/login",
      "is_phishing": true,
      "confidence": 92.0,
      "label": "PHISHING"
    }
  ],
  "language_detected": "pt",
  "translated": true
}
```

### 2.3 Logica de decisao do email

```
1. Detecta idioma do email (langdetect)
2. Se portugues → traduz para ingles (MarianMT)
3. Classifica texto com DistilBERT → email_prob
4. Analisa cada URL do corpo com DomURLs-BERT (sem cascata) → url_probs
5. Combina scores:
   - Se alguma URL tem confianca > 80% → forca PHISHING
   - Senao: score = 0.6 * email_prob + 0.4 * max(url_probs)
6. Decisao final:
   - score > 0.6 → PHISHING
   - 0.4 <= score <= 0.6 → SUSPICIOUS
   - score < 0.4 → LEGITIMO
```

### 2.4 Health check atualizado (US-006)

O endpoint `GET /health` agora retorna informacao sobre os modelos de email:
- `email_model_loaded`: bool
- `translation_model_loaded`: bool

### 2.5 Dockerfile (US-008)

Atualizado para incluir download dos modelos de email e traducao durante o build, evitando download na primeira requisicao.

### 2.6 Thresholds e pesos

| Constante | Valor | Descricao |
|-----------|-------|-----------|
| `EMAIL_PHISHING_THRESHOLD` | 0.6 | Score acima = PHISHING |
| `EMAIL_SUSPICIOUS_THRESHOLD` | 0.4 | Score entre 0.4-0.6 = SUSPICIOUS |
| `EMAIL_WEIGHT` | 0.6 | Peso do score do email na combinacao |
| URL weight | 0.4 | Peso do max score das URLs |
| URL force threshold | 0.8 | URL com confianca > 80% forca PHISHING |

---

## 3. Extensao Chrome (`extensao-phishing/`)

### 3.1 Novo tipo: `EmailAnalysisResponse` (US-009)

Adicionado em `src/utils/api.ts`:

```typescript
interface EmailAnalysisResponse {
  is_phishing: boolean;
  confidence: number;
  label: string;       // "PHISHING" | "SUSPICIOUS" | "LEGITIMO"
  analysis: string;
  inference_ms: number;
  email_score: number;
  url_results: UrlResult[];
  language_detected: string;
  translated: boolean;
}
```

Nova funcao `analyzeEmail()` que faz POST para `/analyze-email` com timeout de 5 segundos e fallback offline.

### 3.2 Content script: `webmail-detector.ts` (US-010)

Novo content script injetado no Gmail e Outlook:

**Sites monitorados:**
- `mail.google.com/*`
- `outlook.live.com/*`
- `outlook.office365.com/*`
- `outlook.office.com/*`

**Funcionamento:**
1. MutationObserver detecta mudancas no DOM (navegacao SPA)
2. Debounce de 500ms para evitar analises repetidas
3. Extrai dados do email:
   - **Gmail:** seletores `h2.hP` (assunto), `span.gD` (remetente), corpo do email
   - **Outlook:** `role="document"`, `aria-label` patterns
4. Extrai todas as URLs dos links `<a href>` no corpo
5. Hash do conteudo para deduplicacao (nao reanalisa mesmo email)
6. Envia mensagem `ANALYZE_EMAIL` para o background script

### 3.3 Handler no background (US-011)

Novo handler `ANALYZE_EMAIL` em `src/background.ts`:

```
Recebe: { subject, body, sender, urls_in_body }
   ↓
Chama API POST /analyze-email
   ↓
Armazena resultado em chrome.storage.session[tabId]
   ↓
Atualiza badge do icone (! vermelho / ? laranja / ✓ verde)
   ↓
Envia notificacao desktop se phishing detectado
   ↓
Retorna resultado para o content script
```

### 3.4 Popup atualizado (US-012)

Novas secoes no popup (`src/popup.tsx` + `src/popup.css`):

- **Badge de idioma:** mostra idioma detectado + indicador de traducao
- **Card de email:** exibe remetente, assunto e classificacao
- **Lista de URLs:** cada URL do email com badge individual (PHISHING/LEGITIMO)
- **Score do email:** barra de confianca com cores (vermelho >= 80%, laranja 60-80%, verde < 60%)
- **Metricas:** label, source, modelo usado (BERT/CatBoost), tempo de inferencia

---

## 4. Testes

### 4.1 Testes unitarios — `test_api.py` (~800 linhas)

| Categoria | O que testa |
|-----------|------------|
| Email models | Validacao dos schemas Pydantic de request/response |
| Language detection | Deteccao de PT, EN, ES |
| Translation | Traducao PT→EN com MarianMT mockado |
| URL analysis | Analise de URLs extraidas do email |
| Endpoint /analyze-email | Request completo, resposta, edge cases |
| Health check | Campos `email_model_loaded` e `translation_model_loaded` |

Estrategia: modelos mockados (sem download de 442 MB nos testes).

### 4.2 Testes de integracao — `test_integration.py` (~970 linhas)

| Cenario | O que testa |
|---------|------------|
| Fluxo end-to-end | Email completo com URLs → classificacao final |
| Extensao → API | Simulacao do fluxo content script → background → API |
| Cache | Mesmo email retorna resultado cacheado |
| API offline | Degradacao graceful quando API indisponivel |
| Docker | Validacao de sintaxe do docker-compose |

---

## 5. Fluxo completo: Email → Extensao → API

```
Usuario abre email no Gmail/Outlook
         |
         v
webmail-detector.ts (content script)
  - MutationObserver detecta novo email
  - Debounce 500ms
  - Extrai: assunto, remetente, corpo, URLs
  - Hash para deduplicacao
         |
         v
background.ts (service worker)
  - Recebe msg ANALYZE_EMAIL
  - Chama POST /analyze-email
         |
         v
app.py (FastAPI)
  - Detecta idioma (langdetect)
  - Traduz se PT (MarianMT)
  - Classifica texto (DistilBERT) → email_prob
  - Classifica cada URL (DomURLs-BERT) → url_probs
  - Combina: 0.6 * email + 0.4 * max(urls)
  - Retorna: label + confidence + url_results
         |
         v
background.ts
  - Armazena em chrome.storage.session
  - Atualiza badge (! / ? / ✓)
  - Notificacao desktop se phishing
         |
         v
popup.tsx
  - Mostra card de email com classificacao
  - Lista URLs com badges individuais
  - Barra de confianca + metricas
```

---

## 6. Arquivos modificados/criados

| Arquivo | Tipo | Linhas |
|---------|------|--------|
| `phishing-api/app.py` | Modificado | +1069 -549 |
| `phishing-api/test_integration.py` | Modificado | +1704 -970 |
| `phishing-api/test_api.py` | Modificado | +1377 -800 |
| `phishing-api/requirements.txt` | Modificado | +39 deps |
| `phishing-api/Dockerfile` | Modificado | +8 linhas |
| `extensao-phishing/src/popup.tsx` | Modificado | +864 -465 |
| `extensao-phishing/src/popup.css` | Modificado | +726 -397 |
| `extensao-phishing/src/background.ts` | Modificado | +680 -388 |
| `extensao-phishing/src/utils/api.ts` | Modificado | +233 -105 |
| `extensao-phishing/src/contents/webmail-detector.ts` | **Novo** | +195 |
| **Total** | | **+4025 -2870** |

---

## 7. Dependencias adicionadas (`requirements.txt`)

| Pacote | Versao | Motivo |
|--------|--------|--------|
| `langdetect` | >= 1.0.9 | Deteccao de idioma do email |
| `transformers` | >= 5.0.0 | DistilBERT email + MarianMT |
| `torch` | >= 2.9.0 | Inferencia dos modelos |

*(demais dependencias ja existiam para o fluxo de URL)*
