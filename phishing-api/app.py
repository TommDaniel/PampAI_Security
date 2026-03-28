import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import logging
import os
from pathlib import Path

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Versao da API
API_VERSION = "2.0.0"

# Variaveis globais para o modelo
model = None
tokenizer = None
MODEL_PATH = os.environ.get("MODEL_PATH", "model")

# CORS origins configuravel via env
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*").split(",")


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_model()
    yield


app = FastAPI(
    title="Phishing Detection API - DomURLs-BERT",
    description="API de detecção de phishing usando DomURLs-BERT",
    version=API_VERSION,
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS if CORS_ORIGINS != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ClientFeatures(BaseModel):
    """Features extraidas client-side pela extensao"""
    length: int = Field(..., description="Comprimento total da URL")
    dom_length: int = Field(..., description="Comprimento do dominio")
    dot: int = Field(..., description="Quantidade de pontos na URL")
    hyphen: int = Field(..., description="Quantidade de hifens na URL")
    slash: int = Field(..., description="Quantidade de barras na URL")
    at: int = Field(..., description="Quantidade de @ na URL")
    params: int = Field(..., description="Quantidade de parametros na URL")
    shortened: int = Field(..., description="1 se URL encurtada, 0 caso contrario")
    tls: int = Field(..., description="1 se HTTPS, 0 caso contrario")
    vowels_domain: int = Field(..., description="Quantidade de vogais no dominio")
    email: int = Field(..., description="1 se contem email na URL, 0 caso contrario")


class PhishingRequest(BaseModel):
    """Modelo de entrada para a API"""
    url: str = Field(..., description="URL a ser analisada")
    client_features: ClientFeatures = Field(..., description="Features extraidas client-side")


class PhishingResponse(BaseModel):
    """Modelo de resposta da API"""
    url: str = Field(..., description="URL analisada")
    is_phishing: bool = Field(..., description="Resultado: e phishing?")
    confidence: float = Field(..., description="Confianca da predicao (0-1)")
    label: str = Field(..., description="Label: PHISHING ou LEGITIMO")
    analysis: str = Field(..., description="Analise textual da decisao")
    inference_ms: float = Field(..., description="Tempo de inferencia em ms")


def load_model():
    """Carrega o modelo DomURLs-BERT e o tokenizer"""
    global model, tokenizer

    try:
        model_path = Path(MODEL_PATH)

        if not model_path.exists():
            raise FileNotFoundError(f"Diretorio do modelo nao encontrado: {MODEL_PATH}")

        logger.info(f"Carregando modelo de {MODEL_PATH}...")

        tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
        model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)

        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)
        model.eval()

        logger.info(f"Modelo carregado com sucesso! Device: {device}")

    except Exception as e:
        logger.error(f"Erro ao carregar modelo: {str(e)}")
        raise


def create_feature_text(url: str, client_features: ClientFeatures) -> str:
    """
    Cria representacao textual para o modelo.
    TODO (US-002): Corrigir para formato de treino [URL]...[WHOIS]...[EXTRA]...
    TODO (US-003): Integrar features server-side (WHOIS, DNS)
    """
    text_parts = [f"URL: {url}"]

    for key, value in client_features.model_dump().items():
        text_parts.append(f"{key}: {value}")

    return " | ".join(text_parts)


def predict_phishing(url: str, client_features: ClientFeatures) -> tuple:
    """
    Faz predicao usando DomURLs-BERT.

    Returns:
        tuple: (is_phishing, confidence, label, analysis, inference_ms)
    """
    start_time = time.perf_counter()

    feature_text = create_feature_text(url, client_features)

    inputs = tokenizer(
        feature_text,
        return_tensors="pt",
        truncation=True,
        max_length=512,  # TODO (US-002): corrigir para 128
        padding=True,
    )

    device = next(model.parameters()).device
    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        probabilities = torch.softmax(logits, dim=-1)

    # classe 0 = legitimo, classe 1 = phishing
    phishing_prob = probabilities[0][1].item()
    is_phishing = phishing_prob > 0.5
    confidence = phishing_prob if is_phishing else 1.0 - phishing_prob

    label = "PHISHING" if is_phishing else "LEGITIMO"

    if is_phishing:
        if confidence >= 0.9:
            analysis = f"URL classificada como PHISHING com alta confianca ({confidence:.1%}). DomURLs-BERT identificou padroes fortemente suspeitos."
        elif confidence >= 0.7:
            analysis = f"URL classificada como PHISHING ({confidence:.1%}). DomURLs-BERT detectou caracteristicas suspeitas."
        else:
            analysis = f"URL classificada como PHISHING com baixa confianca ({confidence:.1%}). Recomenda-se cautela."
    else:
        if confidence >= 0.9:
            analysis = f"URL classificada como LEGITIMA com alta confianca ({confidence:.1%})."
        elif confidence >= 0.7:
            analysis = f"URL classificada como LEGITIMA ({confidence:.1%})."
        else:
            analysis = f"URL classificada como LEGITIMA com baixa confianca ({confidence:.1%}). Recomenda-se cautela."

    inference_ms = (time.perf_counter() - start_time) * 1000

    return is_phishing, confidence, label, analysis, inference_ms


@app.get("/health")
async def health_check():
    """Endpoint de health check"""
    if model is None or tokenizer is None:
        raise HTTPException(status_code=503, detail="Modelo nao carregado")

    device = str(next(model.parameters()).device)

    return {
        "status": "healthy",
        "model_loaded": True,
        "device": device,
        "version": API_VERSION,
    }


@app.post("/predict", response_model=PhishingResponse)
async def predict(request: PhishingRequest):
    """
    Endpoint principal para deteccao de phishing.
    Recebe URL + client_features e retorna predicao do DomURLs-BERT.
    """
    if model is None or tokenizer is None:
        raise HTTPException(status_code=503, detail="Modelo nao carregado")

    try:
        is_phishing, confidence, label, analysis, inference_ms = predict_phishing(
            request.url, request.client_features
        )

        response = PhishingResponse(
            url=request.url,
            is_phishing=is_phishing,
            confidence=confidence,
            label=label,
            analysis=analysis,
            inference_ms=round(inference_ms, 2),
        )

        logger.info(
            f"Predicao: {label} ({confidence:.2%}) | URL: {request.url} | "
            f"Inferencia: {inference_ms:.1f}ms"
        )

        return response

    except Exception as e:
        logger.error(f"Erro na predicao: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro na predicao: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
