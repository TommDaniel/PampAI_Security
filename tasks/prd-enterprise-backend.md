# PRD: Backend Enterprise — Persistencia, Autenticacao, Dashboard e Alertas

## Introduction

Evoluir a plataforma anti-phishing de uma aplicacao stateless para um sistema enterprise com visibilidade centralizada. Hoje a API (FastAPI) faz apenas inferencia e loga em stdout; a extensao (Plasmo MV3) guarda dados apenas no `chrome.storage.local` do usuario. Nao existe autenticacao, banco de dados, nem qualquer forma de supervisores verem o que acontece na organizacao.

Esta PRD adiciona: PostgreSQL para persistencia de eventos, autenticacao por API Key por organizacao, dashboard interativo para supervisores, e sistema de alertas (webhook + email) quando phishing e detectado. A extensao recebe mudancas menores para enviar identificacao de usuario/org em cada request e disparar alertas.

## Goals

- Persistir cada evento de analise (URL e email) em PostgreSQL com atribuicao a usuario e organizacao
- Autenticar requests da extensao via API Key por organizacao (header `X-API-Key`)
- Prover dashboard web interativo para supervisores visualizarem eventos, metricas e tendencias
- Alertar supervisores em tempo real via webhook e email quando phishing e detectado
- Manter retrocompatibilidade — endpoints existentes (`/predict`, `/predict-batch`, `/analyze-email`) continuam funcionando sem API Key (modo anonimo)
- Deploy via Docker Compose (PostgreSQL + API + Dashboard) para demo/TCC

## User Stories

### US-001: Schema PostgreSQL e conexao
**Description:** As a developer, I need a PostgreSQL database with the data model so the API can persist events, users, and organizations.

**Acceptance Criteria:**
- [ ] Adicionar `sqlalchemy>=2.0`, `asyncpg`, `alembic` ao `requirements.txt`
- [ ] Criar `phishing-api/database.py` com engine async, sessionmaker, e Base declarativa
- [ ] Criar `phishing-api/models.py` com tabelas:
  - `organizations` (id UUID PK, name, api_key_hash, webhook_url nullable, alert_email nullable, created_at, updated_at)
  - `users` (id UUID PK, org_id FK, email, name nullable, created_at)
  - `analysis_events` (id UUID PK, org_id FK, user_id FK nullable, event_type ENUM('url','email'), url nullable, is_phishing bool, confidence float, label str, source str, inference_ms float, metadata JSONB, created_at)
- [ ] Criar migration inicial com Alembic (`alembic init`, `alembic revision --autogenerate`)
- [ ] Adicionar servico `postgres` ao `docker-compose.yml` (imagem `postgres:16-alpine`, volume persistente, healthcheck)
- [ ] API conecta ao PostgreSQL no startup e desconecta no shutdown (lifespan events)
- [ ] Typecheck/lint passa

### US-002: Autenticacao por API Key
**Description:** As a IT admin, I want API key authentication so only authorized extensions from my organization can send data.

**Acceptance Criteria:**
- [ ] Criar `phishing-api/auth.py` com dependency `get_current_org(request)` que:
  - Le header `X-API-Key`
  - Se ausente: retorna `None` (modo anonimo — comportamento atual preservado)
  - Se presente: busca org pelo hash da key (SHA-256); retorna 401 se invalida
- [ ] Criar script CLI `phishing-api/manage.py` com comandos:
  - `create-org --name "Empresa X"` → gera API Key, printa, salva hash no DB
  - `list-orgs` → lista organizacoes
  - `rotate-key --org-id UUID` → gera nova key, invalida anterior
- [ ] Endpoints existentes (`/predict`, `/predict-batch`, `/analyze-email`, `/health`) continuam funcionando sem `X-API-Key`
- [ ] Quando `X-API-Key` e fornecida e valida, o `org_id` fica disponivel no request state
- [ ] Retornar 401 com `{"detail": "Invalid API key"}` para keys invalidas
- [ ] Typecheck/lint passa

### US-003: Endpoint POST /events para persistir analises
**Description:** As a developer, I need an endpoint to receive and store analysis events so the organization has a historical record.

**Acceptance Criteria:**
- [ ] Criar endpoint `POST /events` que aceita:
  ```json
  {
    "event_type": "url" | "email",
    "url": "string (opcional)",
    "is_phishing": true,
    "confidence": 0.87,
    "label": "PHISHING",
    "source": "api",
    "inference_ms": 42.5,
    "user_email": "user@empresa.com",
    "metadata": {}
  }
  ```
- [ ] Requer `X-API-Key` (retorna 401 se ausente/invalida)
- [ ] Faz upsert do user por email+org_id (cria se nao existe)
- [ ] Persiste `AnalysisEvent` no PostgreSQL
- [ ] Retorna 201 com `{ "event_id": "uuid", "status": "stored" }`
- [ ] Typecheck/lint passa

### US-004: Persistencia automatica nos endpoints existentes
**Description:** As a developer, I want existing prediction endpoints to automatically persist events when an API key is provided, so organizations get data without changing the extension's reporting flow.

**Acceptance Criteria:**
- [ ] Nos endpoints `/predict` e `/analyze-email`, se `X-API-Key` e valida E header `X-User-Email` esta presente:
  - Persistir o resultado como `AnalysisEvent` automaticamente (fire-and-forget, nao bloqueia response)
  - Popular `org_id` da key, `user_email` do header
- [ ] Se nao ha API Key, comportamento identico ao atual (sem persistencia)
- [ ] Latencia dos endpoints nao aumenta mais que 5ms (persistencia assincrona)
- [ ] Response dos endpoints nao muda (retrocompativel)
- [ ] Typecheck/lint passa

### US-005: Endpoint GET /reports/{org_id}/summary
**Description:** As a security supervisor, I want a summary report of my organization's phishing events so I can assess the threat landscape.

**Acceptance Criteria:**
- [ ] Criar endpoint `GET /reports/{org_id}/summary` com query params:
  - `period`: "7d" | "30d" | "90d" (default "30d")
  - `page`: int (default 1)
  - `per_page`: int (default 50, max 200)
- [ ] Requer `X-API-Key` valida E que a key pertenca ao `org_id` solicitado
- [ ] Retorna:
  ```json
  {
    "org_id": "uuid",
    "period": "30d",
    "total_events": 1234,
    "phishing_detected": 89,
    "phishing_rate": 0.072,
    "top_users_targeted": [{"email": "...", "phishing_count": 12}],
    "top_domains": [{"domain": "...", "count": 8}],
    "daily_counts": [{"date": "2026-04-01", "total": 45, "phishing": 3}],
    "recent_events": [{ "...paginated event list..." }]
  }
  ```
- [ ] Queries usam indices adequados (org_id + created_at)
- [ ] Typecheck/lint passa

### US-006: Sistema de alertas — webhook
**Description:** As a security supervisor, I want to receive a webhook notification when phishing is detected so I can respond immediately.

**Acceptance Criteria:**
- [ ] Criar `phishing-api/alerts.py` com funcao `send_alert(org, event, user)` que:
  - Se `org.webhook_url` configurado: envia POST com payload JSON do evento (timeout 5s, fire-and-forget)
  - Loga sucesso/falha do envio
- [ ] Webhook payload:
  ```json
  {
    "alert_type": "phishing_detected",
    "timestamp": "ISO8601",
    "org_name": "...",
    "user_email": "...",
    "event_type": "url" | "email",
    "url": "...",
    "confidence": 0.92,
    "label": "PHISHING"
  }
  ```
- [ ] Alerta disparado automaticamente quando `is_phishing=true` em qualquer evento persistido
- [ ] Falha no webhook nao afeta o response ao cliente
- [ ] Typecheck/lint passa

### US-007: Sistema de alertas — email
**Description:** As a security supervisor, I want to receive email alerts when phishing is detected so I'm notified even without webhook infrastructure.

**Acceptance Criteria:**
- [ ] Estender `alerts.py` com funcao `send_email_alert(org, event, user)` que:
  - Se `org.alert_email` configurado: envia email via SMTP (config via env vars `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`)
  - Assunto: `"[Phishing Alert] {event_type} detectado — {org.name}"`
  - Corpo: template HTML simples com detalhes do evento
- [ ] Adicionar env vars SMTP ao `docker-compose.yml` (com defaults vazios — alertas por email desabilitados se nao configurado)
- [ ] Falha no envio de email nao afeta o response ao cliente
- [ ] Typecheck/lint passa

### US-008: Endpoint de configuracao de alertas
**Description:** As a IT admin, I want to configure webhook URLs and alert emails for my organization via API.

**Acceptance Criteria:**
- [ ] Criar endpoint `PATCH /orgs/{org_id}/alerts` que aceita:
  ```json
  {
    "webhook_url": "https://hooks.slack.com/...",
    "alert_email": "security@empresa.com"
  }
  ```
- [ ] Requer `X-API-Key` valida pertencente ao `org_id`
- [ ] Valida URL (formato valido) e email (formato valido)
- [ ] Atualiza org no banco
- [ ] Retorna 200 com org atualizada
- [ ] Typecheck/lint passa

### US-009: Dashboard — Backend (API de dados)
**Description:** As a developer, I need API endpoints that serve data for the supervisor dashboard.

**Acceptance Criteria:**
- [ ] Criar endpoint `GET /dashboard/{org_id}/stats` retornando:
  - Contadores: total_events, phishing_count, safe_count, email_events, url_events (no periodo)
  - Serie temporal: eventos por dia nos ultimos 30 dias
  - Taxa de phishing por dia
- [ ] Criar endpoint `GET /dashboard/{org_id}/events` com paginacao e filtros:
  - `event_type`: "url" | "email" | "all"
  - `is_phishing`: true | false | null (todos)
  - `user_email`: filtro parcial
  - `date_from`, `date_to`
  - `page`, `per_page`
- [ ] Criar endpoint `GET /dashboard/{org_id}/users` listando usuarios da org com contadores
- [ ] Todos requerem `X-API-Key` valida da org
- [ ] Typecheck/lint passa

### US-010: Dashboard — Frontend (aplicacao web)
**Description:** As a security supervisor, I want an interactive web dashboard so I can monitor phishing events, view trends, and manage my organization.

**Acceptance Criteria:**
- [ ] Criar `dashboard/` na raiz do projeto com app React (Vite + TypeScript + Tailwind CSS)
- [ ] Pagina de login: campo API Key → valida via `GET /health` com header, redireciona para dashboard
- [ ] Pagina principal com:
  - Cards de metricas: total eventos, phishing detectados, taxa de phishing, usuarios ativos
  - Grafico de linha: eventos por dia (total vs phishing) — usar Recharts
  - Tabela paginada de eventos recentes com filtros (tipo, status, usuario, data)
- [ ] Pagina de usuarios: lista usuarios com contadores de eventos e phishing
- [ ] Pagina de configuracoes: webhook URL, alert email, rotacao de API Key
- [ ] Responsivo (funciona em desktop e tablet)
- [ ] Adicionar servico `dashboard` ao `docker-compose.yml` (build + nginx)
- [ ] Typecheck/lint passa
- [ ] Verify in browser using dev-browser skill

### US-011: Extensao — managed storage e identificacao
**Description:** As a IT admin, I want to configure the extension via Chrome managed storage (GPO/MDM) so deployment is centralized.

**Acceptance Criteria:**
- [ ] Criar `extensao-phishing/assets/managed_schema.json` com JSON Schema:
  ```json
  {
    "type": "object",
    "properties": {
      "orgId": { "type": "string" },
      "userEmail": { "type": "string" },
      "apiEndpoint": { "type": "string" },
      "apiKey": { "type": "string" }
    }
  }
  ```
- [ ] Declarar `"managed_schema": "assets/managed_schema.json"` no `storage` do manifest (via Plasmo config em `package.json`)
- [ ] Criar `extensao-phishing/src/utils/config.ts` que:
  - Le `chrome.storage.managed` no startup
  - Faz fallback para `chrome.storage.sync` (configuracao manual existente)
  - Exporta `getConfig(): { orgId?, userEmail?, apiEndpoint, apiKey? }`
- [ ] Typecheck/lint passa

### US-012: Extensao — enviar identificacao nos requests
**Description:** As a developer, I need the extension to include user and org identification in API requests so events are properly attributed.

**Acceptance Criteria:**
- [ ] Modificar `extensao-phishing/src/utils/api.ts` para:
  - Incluir header `X-API-Key` quando `apiKey` disponivel na config
  - Incluir header `X-User-Email` quando `userEmail` disponivel na config
- [ ] Modificar `background.ts`: apos receber resultado de analise (URL ou email), se config tem `apiKey`, disparar `POST /events` com os dados da analise + `user_email` + `event_type`
- [ ] Envio de eventos e fire-and-forget (nao bloqueia o fluxo de analise)
- [ ] Typecheck/lint passa

### US-013: Extensao — ativar logDecision()
**Description:** As a developer, I want to activate the existing logDecision() function so analysis decisions are logged locally.

**Acceptance Criteria:**
- [ ] Em `background.ts`, apos cada analise (URL e email), chamar `logger.logDecision()` com os dados do resultado
- [ ] Verificar que logs aparecem em `chrome.storage.local` via popup ou DevTools
- [ ] Typecheck/lint passa

### US-014: Infraestrutura — Docker Compose completo
**Description:** As a developer, I need the full Docker Compose setup so the entire stack runs with one command.

**Acceptance Criteria:**
- [ ] `docker-compose.yml` com servicos:
  - `postgres`: PostgreSQL 16 Alpine, volume `pgdata`, healthcheck
  - `phishing-api`: build atual + variaveis de DB, depende de postgres (healthy)
  - `dashboard`: build do frontend React, nginx servindo SPA, proxy `/api` para phishing-api
- [ ] Criar `phishing-api/entrypoint.sh` que roda `alembic upgrade head` antes de iniciar uvicorn
- [ ] `.env.example` com todas as variaveis documentadas
- [ ] `docker-compose up` sobe tudo e stack funciona end-to-end
- [ ] Typecheck/lint passa

### US-015: Documentacao de deploy enterprise
**Description:** As a IT admin, I need deployment documentation so I can set up the stack and configure Chrome managed storage for my organization.

**Acceptance Criteria:**
- [ ] Criar `docs/deploy-enterprise.md` com:
  - Pre-requisitos (Docker, dominio, SMTP opcional)
  - Passo-a-passo de deploy (clone, .env, docker-compose up)
  - Como criar organizacao e gerar API Key (`manage.py`)
  - Como configurar Chrome managed storage via GPO (Windows) e managed preferences (macOS)
  - Template JSON para GPO: `extensao-phishing/enterprise/policy_template.json`
  - Como configurar alertas (webhook + email)
- [ ] Typecheck/lint passa

## Functional Requirements

- FR-1: O sistema deve persistir cada evento de analise em PostgreSQL com campos: org_id, user_id, event_type, url, is_phishing, confidence, label, source, inference_ms, metadata, created_at
- FR-2: Requests com header `X-API-Key` valido devem ser associados a organizacao correspondente; keys invalidas retornam 401
- FR-3: Requests sem `X-API-Key` devem funcionar identicamente ao comportamento atual (modo anonimo, sem persistencia)
- FR-4: O dashboard deve mostrar metricas agregadas (total eventos, phishing detectados, taxa, serie temporal) para a organizacao autenticada
- FR-5: O dashboard deve permitir filtrar eventos por tipo, status, usuario e periodo
- FR-6: Quando phishing e detectado e a org tem webhook configurado, o sistema deve enviar POST ao webhook em ate 5 segundos
- FR-7: Quando phishing e detectado e a org tem email configurado, o sistema deve enviar email de alerta via SMTP
- FR-8: A extensao deve ler configuracao de `chrome.storage.managed` com fallback para `chrome.storage.sync`
- FR-9: A extensao deve incluir `X-API-Key` e `X-User-Email` nos requests quando disponiveis
- FR-10: A extensao deve chamar `logDecision()` para cada analise realizada
- FR-11: O stack completo deve subir com `docker-compose up` sem configuracao adicional alem do `.env`

## Non-Goals

- SSO/SAML ou autenticacao por usuario com login/senha — fora de escopo, API Key por org e suficiente
- Multi-tenancy avancado com isolamento de dados por schema — todos os dados ficam no mesmo schema, filtrados por org_id
- Rate limiting ou quotas por organizacao — pode ser adicionado futuramente
- Deploy em Kubernetes ou cloud managed — apenas Docker Compose local
- Historico de alteracoes de configuracao (audit log) — fora de escopo
- App mobile ou notificacoes push — fora de escopo
- Internacionalizacao do dashboard — apenas portugues

## Technical Considerations

- **Database**: PostgreSQL 16 com SQLAlchemy 2.0 async + asyncpg. Alembic para migrations.
- **Indices**: Criar indices compostos em `analysis_events(org_id, created_at)` e `analysis_events(org_id, is_phishing, created_at)` para queries do dashboard.
- **API Key hashing**: SHA-256 do key antes de armazenar. Comparacao via hash (nao reversivel).
- **Persistencia assincrona**: Usar `asyncio.create_task()` para persistir eventos e enviar alertas sem bloquear o response.
- **Dashboard**: React 18 + Vite + TypeScript + Tailwind CSS + Recharts. Servido por nginx em container separado com proxy reverso para API.
- **SMTP**: Configuracao opcional via env vars. Se nao configurado, alertas por email sao silenciosamente desabilitados.
- **Retrocompatibilidade**: Nenhum endpoint existente muda de assinatura. Novas funcionalidades sao opt-in via `X-API-Key`.
- **Managed storage**: MV3 suporta `chrome.storage.managed` nativamente. Schema declarado no manifest, valores injetados via GPO (Windows) ou managed preferences (macOS/Linux).

## Design Considerations

- Dashboard deve ter layout limpo e profissional, adequado para apresentacao de TCC
- Cards de metricas no topo, grafico de tendencia no meio, tabela de eventos embaixo
- Usar cores semanticas: vermelho para phishing, verde para legitimo, amarelo para suspeito
- Tabela de eventos com badges coloridos por label e icones por event_type (URL vs email)

## Success Metrics

- Stack completo sobe com `docker-compose up` em menos de 3 minutos
- Eventos da extensao aparecem no dashboard em tempo real (< 2 segundos de delay)
- Webhook de alerta dispara em < 5 segundos apos deteccao de phishing
- Dashboard carrega metricas de 30 dias para org com 10k eventos em < 1 segundo
- Extensao continua funcionando identicamente sem configuracao enterprise (modo anonimo)

## Open Questions

- Deve haver um limite de retencao de eventos (ex: 90 dias) ou manter tudo indefinidamente?
- O dashboard precisa de export para CSV/PDF dos relatorios?
- Deve haver niveis de permissao dentro da org (admin vs viewer) ou todos os membros tem acesso total?
