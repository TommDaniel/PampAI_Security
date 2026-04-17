# PampAI Security

Sistema de detecção de phishing em URLs e e-mails desenvolvido como Trabalho de Conclusão de Curso (TCC) na Universidade Federal do Pampa (Unipampa).

O projeto combina modelos de machine learning treinados em datasets brasileiros com uma extensão Chrome e uma API enterprise para proteção em tempo real.

---

## Componentes

| Diretório | Descrição |
|---|---|
| [`phishing-api/`](phishing-api/) | API FastAPI com arquitetura em cascata (GBM + BERT), PostgreSQL, autenticação por API Key, dashboard e alertas |
| [`extensao-phishing/`](extensao-phishing/) | Extensão Chrome MV3 que analisa URLs e e-mails em tempo real via API |
| [`benchmark-modelos/`](benchmark-modelos/) | Notebooks de benchmark: modelos leves (LR, SVM, RF, GBM) e grandes (BERT, RoBERTa, DomURLs-BERT) |
| [`modelo-gbm-brasileiro/`](modelo-gbm-brasileiro/) | Treinamento do modelo GBM final com dataset brasileiro balanceado (660k URLs) |
| [`blacklist/`](blacklist/) | Script para coleta e geração de blacklist local bundled na extensão |
| [`whitelist/`](whitelist/) | Whitelist de domínios legítimos para redução de falsos positivos |
| [`docs/`](docs/) | Documentação técnica, análises de features e roadmap enterprise |
| [`Monografia-TCC/`](Monografia-TCC/) | Texto da monografia em LaTeX (submódulo) |

---

## Resultados

### Modelos Leves

| Modelo | F1 | AUC-ROC | MCC | Latência P50 |
|---|---|---|---|---|
| Logistic Regression | 72.0% | 79.3% | 0.44 | 2.87ms |
| Linear SVM | 71.7% | 79.0% | 0.44 | 3.23ms |
| Random Forest | 84.2% | 91.6% | 0.68 | 45ms |
| **Gradient Boosting** | **83.3%** | **91.0%** | **0.66** | **3.36ms** |

### Modelo Final — GBM Brasileiro (660k URLs)

| Métrica | Resultado |
|---|---|
| F1-Score | **87.27%** |
| AUC-ROC | **94.43%** |
| MCC | **0.7432** |
| Latência P50 | 4.18ms |

---

## Como Rodar

### API (Docker Compose)

```bash
cd phishing-api/
cp .env.example .env   # ajuste credenciais
docker compose up -d
```

A API sobe em `http://localhost:8000`. Dashboard em `http://localhost:8000/dashboard-ui/`.

### Extensão Chrome

```bash
cd extensao-phishing/
npm install
npm run build
```

Carregue a pasta `build/` como extensão não empacotada em `chrome://extensions` (modo desenvolvedor).

---

## Clonando com Submodule

```bash
git clone --recurse-submodules git@github.com:TommDaniel/PampAI_Security.git
```

Ou, se já clonou:

```bash
git submodule update --init
```

---

## Tecnologias

- **ML:** Gradient Boosting, BERT, RoBERTa, DomURLs-BERT, DistilBERT
- **Backend:** FastAPI, PostgreSQL, SQLAlchemy (async), Docker
- **Frontend:** Chrome Extension MV3, TypeScript, Plasmo
- **Dataset:** 660k URLs brasileiras (kmack/Phishing\_urls + PhishTank/OpenPhish BR + Tranco/Majestic .br)
