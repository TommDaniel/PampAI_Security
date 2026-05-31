# Explicabilidade dos Modelos — SHAP & Atenção

Notebook que gera a explicabilidade dos **três modelos em produção** do detector de phishing,
para o capítulo *Desenvolvimento* do TCC.

| Modelo | Técnica |
|---|---|
| **DomURLs-BERT** (`amahdaouy/DomURLs_BERT` fine-tuned) | SHAP de tokens + atenção (rollout + heatmap) |
| **DistilBERT email** (`cybersectony/phishing-email-detection-distilbert_v2.4.1`) | SHAP de tokens + atenção |
| **CatBoost** (`catboost_cascata.cbm`, 24 features) | TreeSHAP nativo (beeswarm, bar, waterfall) |

## Como rodar

1. Abra `explicabilidade_modelos.ipynb` no **Google Colab** com runtime **T4 GPU**
   (Runtime > Change runtime type > T4 GPU). A GPU acelera os transformers; o CatBoost roda em CPU.
2. Confirme os caminhos do Drive na **célula 3**:
   - `DOMURLS_DIR`  → `TCC-Finetuning-DomURLs-BERT/modelo-final` (saída do fine-tuning)
   - `CATBOOST_DIR` → `phishing_catboost_cascata` (contém `catboost_cascata.cbm`,
     `dataset_cascata_20k.csv`, `feature_columns.json`)
   - DistilBERT email é baixado do HuggingFace Hub (não precisa de Drive).
3. Rode todas as células. As figuras `.png`/`.html` são salvas em
   `MyDrive/TCC-Explicabilidade/`.

> A máquina local tem GPU **AMD (sem CUDA)**, por isso a explicabilidade roda no Colab (T4),
> onde o restante do treino também foi feito. Atenção é barata (1 forward pass); o SHAP de texto
> é mais pesado, mas roda em poucos minutos no conjunto de exemplos.

## Personalizar exemplos

Edite `EXEMPLOS_URL` / `EXEMPLOS_EMAIL` na célula 3 e re-rode a seção correspondente.

## Build do notebook

O `.ipynb` é gerado por `_gen_notebook.py` (`python _gen_notebook.py`), que monta as células
via JSON para evitar erros de escape. Edite o gerador e re-rode para alterar o notebook.
