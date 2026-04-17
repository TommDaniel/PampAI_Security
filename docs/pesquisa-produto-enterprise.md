# PampAI Security — Produto Enterprise e Roadmap para MVP Vendavel

Data original: 2026-04-09
Ultima atualizacao: 2026-04-11

---

## 1. Mercado Existente

O mercado enterprise e dominado por botoes de report em email (Outlook/Gmail), nao por extensoes de navegacao em tempo real:

| Produto | Tipo | Foco |
|---|---|---|
| **KnowBe4 PhishAlert** | Plugin email | Simulacao + report de phishing por email |
| **Cofense Reporter** | Plugin email | Report + threat intelligence colaborativa |
| **Barracuda PhishLine** | Plugin email | Simulacao + report |
| **Proofpoint ZenWeb** | Extensao browser | Deteccao de URLs em tempo real (mais proximo do PampAI Security) |
| **SmartScreen** | Built-in Edge | Protecao de URL via base Microsoft |
| **Netcraft** | Extensao browser | Hibrido IA + regras + comunidade (enterprise pago) |
| **Google Safe Browsing** | Built-in Chrome | Blacklist reativa (falhou em 84% dos testes Norn Labs 2026) |

**Conclusao de mercado**: Existe um gap real para uma extensao Chrome MV3 independente que:
- Detecta phishing em tempo real com ML (nao blacklist)
- Analisa e-mails dentro do Gmail/Outlook
- Foca no mercado brasileiro (dominios .br, bancos, governo)
- Oferece self-hosting (LGPD/compliance)
- Cobra menos que concorrentes enterprise (R$15-50/usuario/mes)

---

## 2. Estado Atual — O que ja esta implementado

### Extensao Chrome (client-side)
- [x] Manifest V3, Plasmo, React 18, TypeScript
- [x] Pipeline: whitelist → blacklist → cache → API
- [x] Blacklist com 774k+ dominios (5 fontes: OpenPhish, PhishTank, URLhaus, PhishStats, Phishing.Database)
- [x] Whitelist com 32k+ dominios (Tranco, Majestic, curadoria BR)
- [x] Script de atualizacao automatica das listas (`scripts/atualizar_listas.py`)
- [x] Cache com TTL diferenciado (24h legitimo, 7d phishing) e LRU eviction
- [x] Deteccao de e-mails no Gmail (hashchange + polling) e Outlook (MutationObserver)
- [x] Extracao de subject, body, sender e ate 10 URLs do corpo do e-mail
- [x] Badge no icone (vermelho/amarelo/verde) + notificacoes desktop
- [x] Configuracao enterprise via `chrome.storage.managed` (MDM/GPO)
- [x] Identidade: org_id, user_email, api_key, api_endpoint via politica gerenciada
- [x] Popup com resultado de URL, historico de e-mails, configuracoes
- [x] Logging estruturado com decisao log (timestamp, URL, label, confianca, source)
- [x] Fail-open: nunca bloqueia o usuario, mesmo com API offline

### API Backend (server-side)
- [x] FastAPI + Uvicorn, Python 3.11
- [x] DomURLs-BERT (stage 1) + CatBoost (stage 2, cascata)
- [x] DistilBERT para classificacao de e-mails
- [x] MarianMT para traducao PT→EN
- [x] Autenticacao por API Key (32-byte hex, escopo por org)
- [x] PostgreSQL 16 com async SQLAlchemy (asyncpg)
- [x] Auto-persistencia de todos os eventos de analise
- [x] Alertas automaticos via webhook e email (SMTP) ao detectar phishing
- [x] Dashboard web (`/dashboard-ui/`) com Chart.js, login, timeline, eventos, alertas
- [x] CRUD de configuracoes de alertas por organizacao
- [x] Relatorios agregados (`/reports/{org_id}/summary`)
- [x] Batch prediction (`/predict-batch`)
- [x] Endpoint de saude (`/health`)
- [x] Docker Compose (API + PostgreSQL) com health checks
- [x] CORS configuravel, variaveis de ambiente para SMTP/DB
- [x] Graceful degradation: funciona sem PostgreSQL (DB_ENABLED=False)

### Documentacao e Testes
- [x] README da API com instrucoes de deploy
- [x] Testes unitarios (`test_api.py`, `test_auth.py`, `test_dashboard.py`, etc.)
- [x] Testes de integracao (`test_integration.py`)
- [x] Testes de performance (`test_performance.py`)
- [x] Documento comparativo com ferramentas do mercado (`docs/comparativo-ferramentas-phishing.md`)

---

## 3. O que Falta para MVP Vendavel

### 3.1 Critico (sem isso nao vende)

**Onboarding self-service**
- [ ] Pagina de cadastro: empresa se registra, cria org, recebe API key
- [ ] Wizard de setup: instrucoes para instalar extensao e configurar GPO/MDM
- [ ] Download da extensao pre-configurada com org_id embutido (ou link de config)
- Estado atual: criar org requer `POST /admin/orgs` manual — sem UI

**Planos e limites de uso**
- [ ] Definir tiers: Free (1000 analises/mes, 1 usuario), Pro (R$10-15/usuario/mes), Enterprise (on-premise)
- [ ] Rate limiting por org/API key (requests/minuto e requests/mes)
- [ ] Endpoint para consultar uso atual da org (`/billing/{org_id}/usage`)
- Estado atual: sem limites, qualquer API key tem acesso ilimitado

**Landing page / site comercial**
- [ ] Pagina explicando o produto, diferenciais, precos
- [ ] Demo ao vivo: campo para colar URL e ver resultado em tempo real
- [ ] Formulario de contato / trial
- Estado atual: nao existe

**HTTPS e dominio proprio**
- [ ] Dominio (ex: pampasec.com.br)
- [ ] Certificado TLS (Let's Encrypt)
- [ ] API acessivel publicamente (atualmente localhost:8000)
- Estado atual: roda local, sem dominio

### 3.2 Importante (aumenta muito a chance de vender)

**Gestao de usuarios dentro da org**
- [ ] Listar usuarios da org (email, ultimo acesso, eventos)
- [ ] Dashboard do admin: ver quais funcionarios estao protegidos vs. sem extensao
- [ ] Metricas por usuario: quantos phishing detectados, clicks evitados
- Estado atual: eventos sao anonimos (user_email e opcional, vem do MDM)

**Relatorios mais completos**
- [ ] Relatorio mensal exportavel (PDF ou CSV)
- [ ] Top dominios de phishing detectados na org
- [ ] Tendencia temporal (esta semana vs. anterior)
- [ ] Email automatico com resumo mensal para o admin
- Estado atual: `/reports/{org_id}/summary` retorna JSON basico

**Billing / pagamento**
- [ ] Integracao com Stripe ou similar para cobranca automatica
- [ ] Controle de inadimplencia (suspender API key apos X dias)
- Estado atual: nenhum sistema de cobranca

**Teste de carga validado**
- [ ] Benchmark com locust/k6 simulando 100-500 usuarios simultaneos
- [ ] Documentar throughput maximo (req/s) e latencia P95/P99 sob carga
- [ ] Plano de scaling (quantas replicas para N usuarios)
- Estado atual: `test_performance.py` existe mas para testes unitarios, nao carga real

### 3.3 Desejavel (diferencial competitivo)

**Simulacao de phishing**
- [ ] Admin cria campanha de phishing simulado para treinar funcionarios
- [ ] Envia e-mails controlados, mede quem clicou antes vs depois
- [ ] Relatorio de melhoria (KnowBe4 cobra caro por isso)
- Estado atual: nao existe

**Integracao com SIEM/SOC**
- [ ] Webhook ja existe — documentar formato para integracao com Splunk, Elastic, etc.
- [ ] Syslog output opcional
- Estado atual: webhook funciona, mas sem documentacao de integracao

**Exportacao ONNX do modelo**
- [ ] Exportar DomURLs-BERT para ONNX Runtime
- [ ] Reduz latencia de inferencia na CPU em 2-5x
- [ ] Possibilita inferencia no browser (futuro) via ONNX.js
- Estado atual: usa PyTorch direto

**API de feedback**
- [ ] Endpoint para usuario reportar falso positivo/negativo
- [ ] Dados de feedback alimentam re-treino do modelo
- Estado atual: nao existe

**Multi-idioma no dashboard**
- [ ] Dashboard em PT-BR (atualmente misto PT/EN)
- [ ] Extensao com i18n
- Estado atual: parcialmente em portugues

---

## 4. Modelo de Negocio

### Tiers propostos

| Tier | Preco | Limite | Infra | Para quem |
|---|---|---|---|---|
| **Free** | R$0 | 1000 analises/mes, 1 org, 5 usuarios | SaaS (nos hospedamos) | Freelancers, micro-empresas, validacao |
| **Pro** | R$10-15/usuario/mes | 50k analises/mes, alertas, dashboard, relatorios | SaaS | PMEs (10-200 funcionarios) |
| **Enterprise** | Licenca anual + suporte | Ilimitado | On-premise (Docker Compose) | Bancos, governo, saude (500+) |

### Unit economics (Tier Pro, 50 usuarios)

| Item | Valor |
|---|---|
| Receita mensal | 50 x R$12 = R$600 |
| Custo VPS (4vCPU, 8GB) | ~R$150 |
| Custo DB (managed) | ~R$50 |
| Dominio + infra | ~R$20 |
| **Margem** | **~R$380 (63%)** |

Para 200 usuarios: R$2.400/mes receita, ~R$300 custo = 87% margem.
O ponto de breakeven e ~20 usuarios pagantes.

### Infraestrutura

| Escala | Infra | Custo mensal |
|---|---|---|
| Ate 200 usuarios | 1 VPS (4vCPU, 8GB) + PostgreSQL | R$150-250 |
| 200-500 usuarios | 2-3 replicas + load balancer | R$400-800 |
| 500+ usuarios | Kubernetes ou on-premise do cliente | R$800+ ou licenca |

**Ponto critico: BERT na CPU**
- DomURLs-BERT com PyTorch na CPU: ~100-300ms por request
- Com ONNX Runtime: ~30-80ms (2-5x mais rapido)
- Para 200 usuarios, ONNX na CPU com 4 cores aguenta ~50-100 req/s (suficiente)
- A cascata ajuda: maioria dos requests resolve em whitelist/blacklist/cache (custo zero)

---

## 5. Viabilidade em Cenario Real

### Pontos a favor
- Core tecnico pronto (extensao + API + dashboard + alertas)
- Custo de infra baixo (~R$150/mes para comecar)
- Gap real no mercado brasileiro
- Self-hosting atende LGPD sem dor de cabeca
- Concorrentes cobram R$15-50/usuario/mes — espaco para entrar mais barato

### Riscos
- **SLA**: API precisa de 99.9%+ uptime (downtime = funcionarios sem protecao)
- **LGPD**: armazenar URLs + emails e dado sensivel — precisa de politica de retencao
- **Modelo**: DomURLs-BERT e de terceiros — dependencia de manutencao externa
- **Reputacao**: ferramentas de seguranca vendem por confianca. TCC nao tem track record
- **Suporte**: cliente enterprise espera resposta em horas, nao dias

---

## 6. Metricas de Impacto (argumentos de venda)

| Metrica | Como medir | Benchmark |
|---|---|---|
| **Taxa de clique em phishing** | Antes vs depois da extensao | Sem ferramenta: ~30% clicam. Com: ~5% (KnowBe4 2024) |
| **Tempo de deteccao (MTTD)** | Timestamp do evento vs aparicao da URL | Sem ferramenta: horas/dias. Com PampAI Security: segundos |
| **Custo evitado** | Custo medio de breach x prevencao | IBM 2024: US$4.88M por breach |
| **Cobertura** | % funcionarios com extensao ativa | Meta: 95%+ via GPO |
| **Falsos positivos** | URLs legitimas marcadas como phishing | Aceitavel: <2% |

**Pitch de venda**: "Um incidente de phishing custa R$500k+. PampAI Security custa R$10/usuario/mes. Com 50 funcionarios, sao R$500/mes para evitar um breach que pode falir a empresa."

---

## 7. Roadmap Sugerido

### Fase 1 — MVP Vendavel (4-6 semanas)
1. Landing page com demo ao vivo
2. Onboarding self-service (cadastro de org + API key via UI)
3. Dominio + HTTPS + deploy em VPS
4. Rate limiting por API key
5. Plano Free funcional (validacao com usuarios reais)

### Fase 2 — Monetizacao (4-6 semanas)
1. Integracao Stripe (checkout, cobranca, suspensao)
2. Tiers Free/Pro implementados
3. Relatorios mensais em PDF/CSV
4. Gestao de usuarios por org no dashboard
5. Teste de carga com 100-500 usuarios simulados

### Fase 3 — Enterprise (8-12 semanas)
1. ONNX Runtime para reducao de latencia
2. Simulacao de phishing (campanhas de treino)
3. Integracao SIEM (documentacao de webhook para Splunk/Elastic)
4. API de feedback (falso positivo/negativo)
5. Pilot com empresa real (10-20 usuarios, 30 dias)
6. Tier Enterprise (licenca anual + suporte)

---

## 8. Resumo

| Pergunta | Resposta |
|---|---|
| **O core tecnico ta pronto?** | Sim. Extensao, API, modelos, dashboard, alertas, auth, DB — tudo funciona |
| **O que falta pro MVP?** | Onboarding self-service, landing page, dominio/HTTPS, rate limiting |
| **Quanto custa pra comecar?** | ~R$150/mes (VPS + dominio) |
| **Pra quem vender primeiro?** | PMEs brasileiras (10-200 funcionarios) via SaaS |
| **Quanto cobrar?** | R$10-15/usuario/mes (abaixo da concorrencia) |
| **Breakeven?** | ~20 usuarios pagantes |
| **Diferencial principal?** | Foco BR + ML (nao blacklist) + self-hosting + preco |
