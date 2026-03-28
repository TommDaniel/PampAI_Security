# Phishing Detection Fallback API

API de fallback para detecção de phishing usando modelo transformer. Esta API recebe features e confiança do modelo RandomForest e usa um modelo transformer como fallback quando a confiança do RF é baixa.

## Estrutura do Projeto

```
phishing-api/
├── Dockerfile
├── requirements.txt
├── app.py
├── .dockerignore
├── README.md
└── model/          ← Cole aqui os arquivos do modelo treinado
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
