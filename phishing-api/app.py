from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import logging
import os
from pathlib import Path

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_model()
    yield


app = FastAPI(
    title="Phishing Detection Fallback API",
    description="API de fallback para detecção de phishing usando modelo transformer",
    version="1.0.0",
    lifespan=lifespan
)

# Variáveis globais para o modelo
model = None
tokenizer = None
MODEL_PATH = "model"

# Threshold para decisão entre modelos
CONFIDENCE_THRESHOLD = 0.7


class PhishingRequest(BaseModel):
    """Modelo de entrada para a API"""
    features: Dict[str, Any] = Field(..., description="Features extraídas da URL/página")
    rf_confidence: float = Field(..., ge=0.0, le=1.0, description="Confiança do modelo RandomForest")
    rf_prediction: Optional[bool] = Field(None, description="Predição do RandomForest (True=phishing, False=legítimo)")
    url: Optional[str] = Field(None, description="URL original (opcional)")


class PhishingResponse(BaseModel):
    """Modelo de resposta da API"""
    is_phishing: bool = Field(..., description="Resultado final: é phishing?")
    final_confidence: float = Field(..., description="Confiança da decisão final")
    model_used: str = Field(..., description="Modelo que deu a resposta final (RandomForest ou Transformer)")
    rf_confidence: float = Field(..., description="Confiança do RandomForest")
    transformer_confidence: float = Field(..., description="Confiança do Transformer")
    transformer_prediction: bool = Field(..., description="Predição do Transformer")
    analysis: str = Field(..., description="Análise textual da decisão")


def load_model():
    """Carrega o modelo transformer e o tokenizer"""
    global model, tokenizer

    try:
        model_path = Path(MODEL_PATH)

        if not model_path.exists():
            raise FileNotFoundError(f"Diretório do modelo não encontrado: {MODEL_PATH}")

        logger.info(f"Carregando modelo de {MODEL_PATH}...")

        # Carregar tokenizer e modelo
        tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
        model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)

        # Mover para GPU se disponível
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)
        model.eval()

        logger.info(f"Modelo carregado com sucesso! Device: {device}")

    except Exception as e:
        logger.error(f"Erro ao carregar modelo: {str(e)}")
        raise


def predict_with_transformer(features: Dict[str, Any], url: Optional[str] = None) -> tuple:
    """
    Faz predição usando o modelo transformer

    Returns:
        tuple: (is_phishing: bool, confidence: float)
    """
    try:
        # Criar texto a partir das features (adapte conforme seu modelo foi treinado)
        feature_text = create_feature_text(features, url)

        # Tokenizar
        inputs = tokenizer(
            feature_text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True
        )

        # Mover para o mesmo device do modelo
        device = next(model.parameters()).device
        inputs = {k: v.to(device) for k, v in inputs.items()}

        # Fazer predição
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=-1)

        # Assumindo que classe 0 = legítimo, classe 1 = phishing
        phishing_prob = probabilities[0][1].item()
        is_phishing = phishing_prob > 0.5
        confidence = phishing_prob if is_phishing else 1.0 - phishing_prob

        return is_phishing, confidence

    except Exception as e:
        logger.error(f"Erro na predição com transformer: {str(e)}")
        raise


def create_feature_text(features: Dict[str, Any], url: Optional[str] = None) -> str:
    """
    Cria uma representação textual das features para o modelo transformer
    Adapte isso conforme o formato que seu modelo espera
    """
    text_parts = []

    if url:
        text_parts.append(f"URL: {url}")

    # Adicionar features importantes
    for key, value in features.items():
        if value is not None:
            text_parts.append(f"{key}: {value}")

    return " | ".join(text_parts)


def analyze_predictions(
    rf_confidence: float,
    rf_prediction: Optional[bool],
    transformer_confidence: float,
    transformer_prediction: bool
) -> tuple:
    """
    Analisa as predições de ambos os modelos e decide qual usar

    Returns:
        tuple: (final_prediction: bool, final_confidence: float, model_used: str, analysis: str)
    """

    # Se RandomForest tem alta confiança, usa ele
    if rf_confidence >= CONFIDENCE_THRESHOLD:
        analysis = (
            f"RandomForest apresentou alta confiança ({rf_confidence:.2%}), "
            f"sendo usado como modelo principal."
        )
        return rf_prediction, rf_confidence, "RandomForest", analysis

    # Se RandomForest tem baixa confiança, usa Transformer
    else:
        analysis = (
            f"RandomForest apresentou baixa confiança ({rf_confidence:.2%}). "
            f"Usando DomURLs_BERT fine-tuned como fallback com confiança de {transformer_confidence:.2%}."
        )

        # Se as predições discordam, adiciona aviso
        if rf_prediction is not None and rf_prediction != transformer_prediction:
            analysis += (
                f" ATENÇÃO: Modelos discordam "
                f"(RF: {'phishing' if rf_prediction else 'legítimo'}, "
                f"DomURLs_BERT: {'phishing' if transformer_prediction else 'legítimo'})."
            )

        return transformer_prediction, transformer_confidence, "DomURLs_BERT fine-tuned", analysis


@app.get("/")
async def root():
    """Endpoint raiz para verificação de saúde"""
    return {
        "status": "online",
        "service": "Phishing Detection Fallback API",
        "model_loaded": model is not None
    }


@app.get("/health")
async def health_check():
    """Endpoint de health check"""
    if model is None or tokenizer is None:
        raise HTTPException(status_code=503, detail="Modelo não carregado")

    return {
        "status": "healthy",
        "model_loaded": True,
        "device": str(next(model.parameters()).device)
    }


@app.post("/predict", response_model=PhishingResponse)
async def predict(request: PhishingRequest):
    """
    Endpoint principal para detecção de phishing

    Recebe features e confiança do RandomForest, usa o Transformer como fallback
    """
    try:
        if model is None or tokenizer is None:
            raise HTTPException(status_code=503, detail="Modelo não carregado")

        logger.info(f"Recebida requisição - RF confidence: {request.rf_confidence:.2%}")

        # Fazer predição com Transformer
        transformer_prediction, transformer_confidence = predict_with_transformer(
            request.features,
            request.url
        )

        # Analisar qual modelo usar
        final_prediction, final_confidence, model_used, analysis = analyze_predictions(
            request.rf_confidence,
            request.rf_prediction,
            transformer_confidence,
            transformer_prediction
        )

        response = PhishingResponse(
            is_phishing=final_prediction,
            final_confidence=final_confidence,
            model_used=model_used,
            rf_confidence=request.rf_confidence,
            transformer_confidence=transformer_confidence,
            transformer_prediction=transformer_prediction,
            analysis=analysis
        )

        logger.info(
            f"Resposta: {model_used} - "
            f"{'Phishing' if final_prediction else 'Legítimo'} "
            f"({final_confidence:.2%})"
        )

        return response

    except Exception as e:
        logger.error(f"Erro na predição: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro na predição: {str(e)}")


@app.post("/predict-batch")
async def predict_batch(requests: list[PhishingRequest]):
    """Endpoint para predições em lote"""
    try:
        results = []
        for req in requests:
            result = await predict(req)
            results.append(result)
        return results
    except Exception as e:
        logger.error(f"Erro na predição em lote: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro na predição: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
