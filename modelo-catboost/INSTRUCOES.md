# Treino CatBoost — Segundo Estagio da Cascata

## Arquitetura

```
URL -> [BERT URL bruta] -> confiante? -> decisao final
                        -> incerto?  -> [WHOIS+DNS+TLS] -> [CatBoost] -> decisao
```

## Como executar

1. Abra `treino_catboost_cascata.ipynb` no Google Colab
2. Runtime > Change runtime type > CPU (T4 nao necessario)
3. Faca upload do `dataset_phishing_brasileiro.csv` (da pasta `benchmark-modelos/`)
4. Execute todas as celulas
5. **Cel 5 demora ~2-4h** (extrai WHOIS/DNS/TLS para 20k URLs)

## Apos o treino

1. Baixe `catboost_cascata.cbm` e `feature_columns.json` do Google Drive
2. Copie para `phishing-api/model/`
3. Integre a cascata na API (Parte 3 do plano)

## Features (22 total)

### Client (11) — extraidas da URL
length, dom_length, dot, hyphen, slash, at, params, shortened, tls, vowels_domain, email

### Server numericas (9) — extraidas via WHOIS/DNS/TLS
redirects, dom_age, dom_expire, mx_servers, nameservers, dom_spf, dom_in_ip, tls_validity_days, tls_san_count

### Server categoricas (3) — CatBoost trata nativamente
registrar, country_code, tls_issuer

### Binaria (1)
whois_privacy
