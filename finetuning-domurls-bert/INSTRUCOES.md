# Fine-tuning DomURLs-BERT com Tokens Especiais

## Problema

O DomURLs-BERT base (`amahdaouy/DomURLs_BERT`) não possui os tokens `[URL]`, `[WHOIS]`,
`[EXTRA]`, `[AGE]`, `[REG]`, `[EXPIRE]` no vocabulário. Quando o modelo anterior foi
treinado, esses tokens foram mapeados para `[UNK]`, corrompendo as predições em produção.

## Solução

Antes do fine-tuning:

```python
tokenizer.add_special_tokens({'additional_special_tokens': ['[URL]', '[WHOIS]', '[EXTRA]', '[AGE]', '[REG]', '[EXPIRE]']})
model.resize_token_embeddings(len(tokenizer))
```

## Como executar

1. Abra `finetuning_domurls_bert.ipynb` no Google Colab
2. Selecione Runtime > Change runtime type > T4 GPU
3. Faça upload do `dataset_multimodal.csv` (da pasta `benchmark-modelos/`)
4. Execute todas as células

## Após o treino

1. Baixe a pasta `modelo-final/` do Google Drive
2. Copie para `phishing-api/model/` (substituindo o modelo atual)
3. Rebuild o Docker: `docker-compose build && docker-compose up -d`
4. A API detecta automaticamente se o tokenizer tem tokens especiais e usa o modo correto

## Arquivos necessários

- `finetuning_domurls_bert.ipynb` — notebook de treino
- `../benchmark-modelos/dataset_multimodal.csv` — dataset (upload no Colab)
