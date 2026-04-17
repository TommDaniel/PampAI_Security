# Phishing Detection API — Enterprise

API de detecção de phishing com arquitetura em cascata (BERT + CatBoost), persistência PostgreSQL, autenticação por API Key, dashboard interativo e sistema de alertas (webhook + email).

---

## Deploy Enterprise (Docker Compose)

### Pré-requisitos

- Docker 24+ e Docker Compose v2
- Arquivos do modelo treinado (pasta `model/`)

### 1. Clonar e configurar variáveis de ambiente

```bash
cp .env.example .env
```

Edite `.env` e ajuste as credenciais:

```env
POSTGRES_USER=phishing
POSTGRES_PASSWORD=SuaSenhaSegura123
POSTGRES_DB=phishing

API_PORT=8000
CORS_ORIGINS=https://meusite.exemplo.com

# SMTP (opcional — para alertas por email)
SMTP_HOST=smtp.exemplo.com
SMTP_PORT=587
SMTP_USER=alertas@exemplo.com
SMTP_PASSWORD=SenhaSMTP
SMTP_FROM=alertas@exemplo.com
```

### 2. Subir a stack completa

```bash
# A partir da pasta phishing-api/
docker compose up -d
```

O Docker Compose sobe dois serviços:
- **postgres** — PostgreSQL 16 com volume persistente e health check
- **phishing-api** — FastAPI, aguarda o Postgres estar pronto antes de iniciar

As tabelas são criadas automaticamente na primeira inicialização (sem migration manual).

### 3. Verificar saúde dos serviços

```bash
docker compose ps
curl http://localhost:8000/health
```

---

## Autenticação por API Key

### Criar uma organização

```bash
curl -X POST http://localhost:8000/admin/orgs \
  -H "Content-Type: application/json" \
  -d '{"org_id": "minha-empresa", "name": "Minha Empresa Ltda"}'
```

Resposta:
```json
{
  "org_id": "minha-empresa",
  "api_key": "a1b2c3d4e5f6..."
}
```

Guarde a `api_key` — ela não pode ser recuperada depois.

### Usar a API Key nos requests

Inclua o header `X-API-Key` em todas as chamadas autenticadas:

```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -H "X-API-Key: a1b2c3d4e5f6..." \
  -d '{"url": "http://exemplo.com", "rf_confidence": 0.65, "rf_prediction": false}'
```

> **Nota:** a API aceita requests anônimos (sem `X-API-Key`). Apenas os endpoints de relatórios, dashboard e configuração de alertas exigem autenticação.

---

## Dashboard Interativo

Acesse o dashboard web em:

```
http://localhost:8000/dashboard-ui/
```

Na tela de login, informe:
- **Org ID**: o `org_id` criado acima (ex: `minha-empresa`)
- **API Key**: a chave gerada no passo anterior

O dashboard exibe:
- Total de análises, detecções de phishing, emails e URLs analisados
- Gráfico de linha com evolução diária (últimos 30 dias)
- Tabela paginada de todos os eventos com filtros

---

## Sistema de Alertas

### Configurar webhook

```bash
curl -X POST http://localhost:8000/alerts/minha-empresa/configs \
  -H "Content-Type: application/json" \
  -H "X-API-Key: a1b2c3d4e5f6..." \
  -d '{
    "alert_type": "webhook",
    "endpoint": "https://hooks.slack.com/services/T00/B00/XXXX",
    "enabled": true
  }'
```

A API fará um POST para o URL configurado a cada detecção de phishing com payload:

```json
{
  "event": "phishing_detected",
  "org_id": "minha-empresa",
  "event_type": "url",
  "is_phishing": true,
  "confidence": 94.5,
  "label": "PHISHING",
  "url": "http://site-suspeito.xyz/login",
  "created_at": "2026-04-09T14:30:00.000000"
}
```

### Configurar alerta por email

```bash
curl -X POST http://localhost:8000/alerts/minha-empresa/configs \
  -H "Content-Type: application/json" \
  -H "X-API-Key: a1b2c3d4e5f6..." \
  -d '{
    "alert_type": "email",
    "endpoint": "seguranca@minha-empresa.com",
    "enabled": true
  }'
```

O campo `endpoint` é o endereço de destino do email. Configure o SMTP via variáveis de ambiente no `.env`.

### Gerenciar configurações de alerta

```bash
# Listar configurações
curl http://localhost:8000/alerts/minha-empresa/configs \
  -H "X-API-Key: a1b2c3d4e5f6..."

# Desativar um alerta (substitua {config_id} pelo ID retornado no POST)
curl -X PUT http://localhost:8000/alerts/minha-empresa/configs/{config_id} \
  -H "Content-Type: application/json" \
  -H "X-API-Key: a1b2c3d4e5f6..." \
  -d '{"enabled": false}'

# Remover um alerta
curl -X DELETE http://localhost:8000/alerts/minha-empresa/configs/{config_id} \
  -H "X-API-Key: a1b2c3d4e5f6..."
```

---

## Relatórios via API

### Resumo da organização

```bash
curl http://localhost:8000/reports/minha-empresa/summary \
  -H "X-API-Key: a1b2c3d4e5f6..."
```

Resposta:
```json
{
  "org_id": "minha-empresa",
  "total_events": 1250,
  "phishing_count": 87,
  "legitimate_count": 1163,
  "avg_confidence": 91.3,
  "last_event_at": "2026-04-09T14:30:00.000000"
}
```

### Eventos paginados

```bash
curl "http://localhost:8000/dashboard/minha-empresa/events?page=1&limit=50&is_phishing=true" \
  -H "X-API-Key: a1b2c3d4e5f6..."
```

### Timeline diária

```bash
curl "http://localhost:8000/dashboard/minha-empresa/timeline?days=7" \
  -H "X-API-Key: a1b2c3d4e5f6..."
```

---

## Configuração da Extensão (Enterprise / MDM)

Para implantar a extensão em ambientes corporativos via GPO (Windows), Intune ou MDM:

### 1. Publicar a política gerenciada

Crie a política com os campos abaixo (JSON):

```json
{
  "org_id": "minha-empresa",
  "user_email": "usuario@empresa.com",
  "api_key": "a1b2c3d4e5f6...",
  "api_endpoint": "https://api.phishing.empresa.com"
}
```

| Campo | Descrição |
|---|---|
| `org_id` | Identificador da organização |
| `user_email` | Email do usuário (para atribuição de eventos) |
| `api_key` | Chave de API da organização |
| `api_endpoint` | URL da API (substitui o padrão) |

### 2. Comportamento da extensão

- Lê a política via `chrome.storage.managed` (somente leitura para o usuário)
- Inclui `X-API-Key` e `X-User-Email` nos headers de cada análise
- Registra decisões localmente via `logDecision()` (últimas 500 entradas)
- Falha de forma segura (fail-open): se a API estiver indisponível, a extensão permite a navegação

---

## Endpoints Enterprise — Referência Rápida

| Método | Endpoint | Auth | Descrição |
|--------|----------|------|-----------|
| POST | `/admin/orgs` | — | Criar organização e gerar API Key |
| GET | `/reports/{org_id}/summary` | obrig. | Resumo de eventos da organização |
| GET | `/dashboard/{org_id}/events` | obrig. | Lista paginada de eventos |
| GET | `/dashboard/{org_id}/timeline` | obrig. | Contagens diárias |
| GET | `/alerts/{org_id}/configs` | obrig. | Listar configurações de alerta |
| POST | `/alerts/{org_id}/configs` | obrig. | Criar configuração de alerta |
| PUT | `/alerts/{org_id}/configs/{id}` | obrig. | Atualizar alerta |
| DELETE | `/alerts/{org_id}/configs/{id}` | obrig. | Remover alerta |

---

## Hardening para Produção

1. **Senha forte no PostgreSQL**: troque o valor padrão `phishing` por uma senha aleatória longa.
2. **CORS restrito**: configure `CORS_ORIGINS` com os domínios exatos (não use `*`).
3. **HTTPS**: coloque um proxy reverso (nginx/Caddy/Traefik) com TLS na frente da API.
4. **Endpoint `/admin/orgs` protegido**: restrinja acesso por IP ou remova da rede pública após bootstrap.
5. **Backup do volume**: o volume `postgres_data` contém todos os eventos — inclua-o na sua rotina de backup.

---

## Logs e Monitoramento

```bash
# Logs da API em tempo real
docker compose logs -f phishing-api

# Logs do banco de dados
docker compose logs -f postgres

# Reiniciar apenas a API (sem derrubar o banco)
docker compose restart phishing-api
```

---

## API Básica (uso sem banco de dados)

> Esta seção documenta o uso sem PostgreSQL. Neste modo, os endpoints de autenticação, relatórios, dashboard e alertas ficam indisponíveis (503), mas a detecção de phishing funciona normalmente.

---

## Estrutura do Projeto

```
phishing-api/
├── Dockerfile
├── docker-compose.yml      ← Stack enterprise (API + PostgreSQL)
├── .env.example            ← Variáveis de ambiente (copie para .env)
├── requirements.txt
├── app.py                  ← FastAPI — endpoints principais
├── auth.py                 ← Autenticação por API Key
├── db.py                   ← Conexão PostgreSQL (SQLAlchemy async)
├── alerts.py               ← Sistema de alertas (webhook + email)
├── migrations/
│   └── 001_init.sql        ← DDL das tabelas (referência — app cria automaticamente)
├── dashboard/
│   └── index.html          ← Dashboard interativo (servido em /dashboard-ui/)
├── README.md
└── model/                  ← Cole aqui os arquivos do modelo treinado
    ├── config.json
    ├── model.safetensors
    ├── tokenizer.json
    ├── special_tokens_map.json
    ├── tokenizer_config.json
    └── whois_cache.json (opcional)
```

## Como Usar

### 1. Adicionar o Modelo

Primeiro, copie todos os arquivos do seu modelo treinado para a pasta `model/`:

```bash
# Criar pasta model se não existir
mkdir model

# Copiar arquivos do modelo
cp /caminho/para/seu/modelo/* model/
```

### 2. Construir a Imagem Docker

```bash
docker build -t phishing-api .
```

### 3. Executar o Container

```bash
# Rodar em porta 8000
docker run -p 8000:8000 phishing-api

# Ou rodar em background
docker run -d -p 8000:8000 --name phishing-api phishing-api
```

### 4. Testar a API

#### Health Check
```bash
curl http://localhost:8000/health
```

#### Fazer Predição
```bash
curl -X POST "http://localhost:8000/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "features": {
      "url_length": 45,
      "has_ip": false,
      "num_dots": 2,
      "has_https": true
    },
    "rf_confidence": 0.65,
    "rf_prediction": false,
    "url": "https://example.com"
  }'
```

## Endpoints da API

### `GET /`
Endpoint raiz para verificação de status.

**Resposta:**
```json
{
  "status": "online",
  "service": "Phishing Detection Fallback API",
  "model_loaded": true
}
```

### `GET /health`
Health check para monitoramento.

**Resposta:**
```json
{
  "status": "healthy",
  "model_loaded": true,
  "device": "cpu"
}
```

### `POST /predict`
Endpoint principal para detecção de phishing.

**Entrada:**
```json
{
  "features": {
    "url_length": 45,
    "has_ip": false,
    "num_dots": 2,
    "has_https": true
  },
  "rf_confidence": 0.65,
  "rf_prediction": false,
  "url": "https://example.com"
}
```

**Saída:**
```json
{
  "is_phishing": false,
  "final_confidence": 0.85,
  "model_used": "Transformer",
  "rf_confidence": 0.65,
  "transformer_confidence": 0.85,
  "transformer_prediction": false,
  "analysis": "RandomForest apresentou baixa confiança (65.00%). Usando Transformer como fallback com confiança de 85.00%."
}
```

### `POST /predict-batch`
Predições em lote.

**Entrada:** Array de objetos de requisição
**Saída:** Array de objetos de resposta

## Lógica de Decisão

A API usa a seguinte lógica para decidir qual modelo utilizar:

1. **RandomForest com alta confiança (≥ 70%)**
   - Usa a predição do RandomForest
   - Retorna a confiança do RF

2. **RandomForest com baixa confiança (< 70%)**
   - Usa o Transformer como fallback
   - Retorna a predição e confiança do Transformer
   - Adiciona aviso se os modelos discordarem

## Configuração Avançada

### Ajustar Threshold de Confiança

Edite a constante `CONFIDENCE_THRESHOLD` em `app.py`:

```python
CONFIDENCE_THRESHOLD = 0.7  # Altere conforme necessário
```

### Usar GPU

Se você tiver GPU disponível, o modelo automaticamente a utilizará. Certifique-se de usar a imagem base do Docker com suporte a CUDA:

```dockerfile
FROM pytorch/pytorch:2.1.2-cuda11.8-cudnn8-runtime
```

### Variáveis de Ambiente

```bash
docker run -p 8000:8000 \
  -e CONFIDENCE_THRESHOLD=0.75 \
  phishing-api
```

## Desenvolvimento Local

### Sem Docker

```bash
# Instalar dependências
pip install -r requirements.txt

# Executar API
python app.py
```

A API estará disponível em `http://localhost:8000`

### Com Docker Compose

Crie um `docker-compose.yml`:

```yaml
version: '3.8'

services:
  phishing-api:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./model:/app/model
    environment:
      - CONFIDENCE_THRESHOLD=0.7
```

Execute:
```bash
docker-compose up
```

## Documentação Interativa

Após iniciar a API, acesse:

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

## Integração com Extensão

Exemplo de código para chamar a API da sua extensão:

```javascript
async function checkPhishingWithFallback(features, rfConfidence, rfPrediction, url) {
  const response = await fetch('http://localhost:8000/predict', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      features: features,
      rf_confidence: rfConfidence,
      rf_prediction: rfPrediction,
      url: url
    })
  });

  const result = await response.json();
  console.log(`Modelo usado: ${result.model_used}`);
  console.log(`É phishing? ${result.is_phishing}`);
  console.log(`Confiança: ${result.final_confidence}`);
  console.log(`Análise: ${result.analysis}`);

  return result;
}
```

## Troubleshooting

### Modelo não carrega
- Verifique se todos os arquivos do modelo estão na pasta `model/`
- Verifique os logs: `docker logs <container-id>`

### Erro de memória
- Reduza o `max_length` no tokenizer
- Use uma versão menor do modelo
- Aumente a memória disponível para o Docker

### API lenta
- Use GPU se disponível
- Considere usar quantização do modelo
- Implemente cache para URLs já analisadas

## Logs

Ver logs do container:
```bash
docker logs -f phishing-api
```

## Parar o Container

```bash
docker stop phishing-api
docker rm phishing-api
```
