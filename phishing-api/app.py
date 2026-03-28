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

from server_features import ServerFeatures, extract_server_features

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


def create_feature_text(
    url: str,
    client_features: ClientFeatures,
    whois_text: str = "[WHOIS] unknown",
    server_features: Optional[ServerFeatures] = None,
) -> str:
    """
    Cria representacao textual no formato de treino do DomURLs-BERT.

    Formato: [URL] <url> <whois_tokens> [EXTRA] feat=val feat=val ...

    Training feature order in [EXTRA]:
      redirects, length, dom_length, dot, hyphen, slash, at, params,
      shortened, tls, dom_age, dom_expire, mx_servers, nameservers,
      dom_google_index, dom_spf, dom_in_ip, vowels_domain, srv_client, email

    Features with value -1 (unknown/failed lookup) are omitted.
    """
    cf = client_features.model_dump()
    sf = server_features or ServerFeatures()

    # Ordered list matching training dataset exactly
    ordered_features = [
        ("redirects", sf.redirects),
        ("length", cf["length"]),
        ("dom_length", cf["dom_length"]),
        ("dot", cf["dot"]),
        ("hyphen", cf["hyphen"]),
        ("slash", cf["slash"]),
        ("at", cf["at"]),
        ("params", cf["params"]),
        ("shortened", cf["shortened"]),
        ("tls", cf["tls"]),
        ("dom_age", sf.dom_age),
        ("dom_expire", sf.dom_expire),
        ("mx_servers", sf.mx_servers),
        ("nameservers", sf.nameservers),
        ("dom_google_index", sf.domain_google_index),
        ("dom_spf", sf.dom_spf),
        ("dom_in_ip", sf.dom_in_ip),
        ("vowels_domain", cf["vowels_domain"]),
        ("srv_client", sf.srv_client),
        ("email", cf["email"]),
    ]

    # Omit features with value -1 (unknown/failed)
    extra_parts = [f"{k}={int(v)}" for k, v in ordered_features if v != -1]
    extra_text = "[EXTRA] " + " ".join(extra_parts) if extra_parts else "[EXTRA] none"

    if server_features is not None:
        whois_text = server_features.whois_text

    return f"[URL] {url} {whois_text} {extra_text}"


async def predict_phishing(url: str, client_features: ClientFeatures) -> tuple:
    """
    Faz predicao usando DomURLs-BERT with server-side feature extraction.

    Returns:
        tuple: (is_phishing, confidence, label, analysis, inference_ms)
    """
    start_time = time.perf_counter()

    server_feats = await extract_server_features(url)
    feature_text = create_feature_text(url, client_features, server_features=server_feats)

    inputs = tokenizer(
        feature_text,
        return_tensors="pt",
        truncation=True,
        max_length=128,
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
        is_phishing, confidence, label, analysis, inference_ms = await predict_phishing(
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
