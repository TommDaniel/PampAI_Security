import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer, MarianMTModel, MarianTokenizer
from langdetect import detect as langdetect_detect
import logging
import os
from pathlib import Path

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Versao da API
API_VERSION = "3.0.0"

# Threshold de phishing — probabilidade minima para classificar como phishing.
# Valor mais alto reduz falsos positivos (sites legitimos marcados como phishing).
PHISHING_THRESHOLD = 0.65

# Cascata: limites de confianca do BERT para decidir sozinho.
# Fora dessa faixa, BERT decide direto. Dentro, aciona o CatBoost (estagio 2).
BERT_CONFIDENT_UPPER = 0.85  # P(phish) >= 0.85 → phishing direto
BERT_CONFIDENT_LOWER = 0.15  # P(phish) <= 0.15 → legitimo direto

# Peso do BERT na combinacao cascata (1-alpha = peso do CatBoost)
CASCADE_BERT_WEIGHT = 0.6

# IDs dos modelos de email e traducao
EMAIL_MODEL_ID = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
TRANSLATION_MODEL_ID = "Helsinki-NLP/opus-mt-tc-big-pt-en"

# Variaveis globais para os modelos
model = None
tokenizer = None
catboost_model = None
email_model = None
email_tokenizer = None
translation_model = None
translation_tokenizer = None
MODEL_PATH = os.environ.get("MODEL_PATH", "model")
CATBOOST_PATH = os.environ.get("CATBOOST_PATH", os.path.join("model", "catboost_cascata.cbm"))

# CORS origins configuravel via env
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*").split(",")


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_model()
    yield


app = FastAPI(
    title="Phishing Detection API - DomURLs-BERT + CatBoost Cascade",
    description="API de detecção de phishing com arquitetura em cascata: BERT (URL) + CatBoost (WHOIS/DNS/TLS)",
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


class EmailRequest(BaseModel):
    """Modelo de entrada para analise de email"""
    subject: str = Field(default="", description="Assunto do email")
    body: str = Field(default="", description="Corpo do email (texto)")
    sender: str = Field(default="", description="Remetente do email")
    urls_in_body: List[str] = Field(default_factory=list, description="URLs encontradas no corpo do email")


class EmailUrlResult(BaseModel):
    """Resultado da analise de uma URL encontrada no email"""
    url: str = Field(..., description="URL analisada")
    is_phishing: bool = Field(..., description="Resultado: e phishing?")
    confidence: float = Field(..., description="Confianca da predicao (0-100)")
    label: str = Field(..., description="Label: PHISHING ou LEGITIMO")


class EmailResponse(BaseModel):
    """Modelo de resposta da analise de email"""
    is_phishing: bool = Field(..., description="Resultado: e phishing?")
    confidence: float = Field(..., description="Confianca da predicao (0-100)")
    label: str = Field(..., description="Label: PHISHING, SUSPICIOUS ou LEGITIMO")
    analysis: str = Field(..., description="Analise textual da decisao")
    inference_ms: float = Field(..., description="Tempo de inferencia em ms")
    email_score: float = Field(..., description="Score do email (0-100)")
    url_results: List[EmailUrlResult] = Field(default_factory=list, description="Resultados das URLs no email")
    language_detected: str = Field(default="", description="Idioma detectado do email")
    translated: bool = Field(default=False, description="Se o email foi traduzido")


class PhishingRequest(BaseModel):
    """Modelo de entrada para a API"""
    url: str = Field(..., description="URL a ser analisada")
    client_features: ClientFeatures = Field(..., description="Features extraidas client-side")
    mode: str = Field(default="cascade", description="Modo: bert, catboost, cascade")


class PhishingResponse(BaseModel):
    """Modelo de resposta da API"""
    url: str = Field(..., description="URL analisada")
    is_phishing: bool = Field(..., description="Resultado: e phishing?")
    confidence: float = Field(..., description="Confianca da predicao (0-100)")
    label: str = Field(..., description="Label: PHISHING ou LEGITIMO")
    analysis: str = Field(..., description="Analise textual da decisao")
    inference_ms: float = Field(..., description="Tempo de inferencia em ms")
    source: str = Field(default="bert", description="Estagio que decidiu: bert ou cascade")


def load_model():
    """Carrega o DomURLs-BERT, CatBoost, DistilBERT email e MarianMT traducao."""
    global model, tokenizer, catboost_model
    global email_model, email_tokenizer, translation_model, translation_tokenizer

    try:
        model_path = Path(MODEL_PATH)

        if not model_path.exists():
            raise FileNotFoundError(f"Diretorio do modelo nao encontrado: {MODEL_PATH}")

        logger.info(f"Carregando DomURLs-BERT de {MODEL_PATH}...")

        tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
        model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)

        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)
        model.eval()

        logger.info(f"BERT carregado! Device: {device}, threshold: {PHISHING_THRESHOLD}")

        # Carregar CatBoost (estagio 2 da cascata) se disponivel
        cb_path = Path(CATBOOST_PATH)
        if cb_path.exists():
            from catboost import CatBoostClassifier
            catboost_model = CatBoostClassifier()
            catboost_model.load_model(str(cb_path))
            logger.info(f"CatBoost cascata carregado de {CATBOOST_PATH}")
        else:
            logger.info("CatBoost nao encontrado — cascata desativada, BERT decide sozinho")

        # Carregar DistilBERT para email phishing detection
        try:
            logger.info(f"Carregando DistilBERT email de {EMAIL_MODEL_ID}...")
            email_tokenizer = AutoTokenizer.from_pretrained(EMAIL_MODEL_ID)
            email_model = AutoModelForSequenceClassification.from_pretrained(EMAIL_MODEL_ID)
            email_model.to(device)
            email_model.eval()
            logger.info(f"DistilBERT email carregado! Device: {device}")
        except Exception as e:
            logger.warning(f"Falha ao carregar modelo de email: {e}")
            email_model = None
            email_tokenizer = None

        # Carregar MarianMT para traducao PT->EN
        try:
            logger.info(f"Carregando MarianMT traducao de {TRANSLATION_MODEL_ID}...")
            translation_tokenizer = MarianTokenizer.from_pretrained(TRANSLATION_MODEL_ID)
            translation_model = MarianMTModel.from_pretrained(TRANSLATION_MODEL_ID)
            translation_model.to(device)
            translation_model.eval()
            logger.info(f"MarianMT traducao carregado! Device: {device}")
        except Exception as e:
            logger.warning(f"Falha ao carregar modelo de traducao: {e}")
            translation_model = None
            translation_tokenizer = None

    except Exception as e:
        logger.error(f"Erro ao carregar modelo: {str(e)}")
        raise


def _bert_predict(url: str) -> float:
    """Executa BERT no URL bruto e retorna P(phishing)."""
    inputs = tokenizer(
        url,
        return_tensors="pt",
        truncation=True,
        max_length=128,
        padding=True,
    )

    device = next(model.parameters()).device
    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = model(**inputs)
        probabilities = torch.softmax(outputs.logits, dim=-1)

    return probabilities[0][1].item()


def detect_and_translate(text: str) -> tuple[str, str, bool]:
    """Detecta idioma do texto e traduz PT->EN se necessario.

    Returns:
        (texto_en, idioma_detectado, foi_traduzido)
    """
    if not text or not text.strip():
        return text, "unknown", False

    try:
        lang = langdetect_detect(text)
    except Exception:
        lang = "unknown"

    if lang == "pt" and translation_model is not None and translation_tokenizer is not None:
        device = next(translation_model.parameters()).device
        inputs = translation_tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
        )
        inputs = {k: v.to(device) for k, v in inputs.items()}

        with torch.no_grad():
            translated_ids = translation_model.generate(**inputs)

        translated_text = translation_tokenizer.decode(translated_ids[0], skip_special_tokens=True)
        return translated_text, lang, True

    return text, lang, False


def _analyze_email_urls(urls: List[str]) -> List[EmailUrlResult]:
    """Analisa URLs encontradas no corpo do email usando apenas BERT (sem cascata CatBoost)."""
    results = []
    for url in urls[:10]:
        prob = _bert_predict(url)
        is_phishing = prob > PHISHING_THRESHOLD
        confidence = (prob if is_phishing else 1.0 - prob) * 100
        label = "PHISHING" if is_phishing else "LEGITIMO"
        results.append(EmailUrlResult(
            url=url,
            is_phishing=is_phishing,
            confidence=round(confidence, 2),
            label=label,
        ))
    return results


async def _catboost_predict(url: str, client_features: ClientFeatures) -> float:
    """Extrai server features e roda CatBoost. Retorna P(phishing)."""
    from server_features import extract_server_features

    server_feats = await extract_server_features(url)
    cf = client_features.model_dump()

    # Montar feature vector na mesma ordem do treino (feature_columns.json)
    feature_vector = [
        # Client features (11)
        cf["length"], cf["dom_length"], cf["dot"], cf["hyphen"],
        cf["slash"], cf["at"], cf["params"], cf["shortened"],
        cf["tls"], cf["vowels_domain"], cf["email"],
        # Server features numericas (9)
        server_feats.redirects, server_feats.dom_age, server_feats.dom_expire,
        server_feats.mx_servers, server_feats.nameservers, server_feats.dom_spf,
        server_feats.dom_in_ip,
        getattr(server_feats, 'tls_validity_days', -1),
        getattr(server_feats, 'tls_san_count', -1),
        # Server features categoricas (3)
        getattr(server_feats, 'registrar', 'unknown'),
        getattr(server_feats, 'country_code', 'unknown'),
        getattr(server_feats, 'tls_issuer', 'unknown'),
        # WHOIS privacy (1)
        getattr(server_feats, 'whois_privacy', -1),
    ]

    proba = catboost_model.predict_proba([feature_vector])
    return proba[0][1]


async def predict_phishing(url: str, client_features: ClientFeatures, mode: str = "cascade") -> tuple:
    """
    Predicao em cascata: BERT primeiro, CatBoost se incerto.

    Args:
        mode: "bert" (BERT sozinho), "catboost" (CatBoost sozinho), "cascade" (padrao)

    Returns:
        tuple: (is_phishing, confidence, label, analysis, inference_ms, source)
    """
    start_time = time.perf_counter()

    if mode == "catboost" and catboost_model is not None:
        # Modo CatBoost sozinho — ignora BERT
        try:
            cb_prob = await _catboost_predict(url, client_features)
            final_prob = cb_prob
            source = "catboost"
        except Exception as e:
            logger.warning(f"CatBoost falhou: {e}")
            final_prob = 0.5
            source = "catboost_error"
    elif mode == "bert":
        # Modo BERT sozinho — ignora CatBoost
        bert_prob = _bert_predict(url)
        final_prob = bert_prob
        source = "bert"
    else:
        # Modo cascata (padrao)
        bert_prob = _bert_predict(url)
        source = "bert"

        if catboost_model is not None and BERT_CONFIDENT_LOWER < bert_prob < BERT_CONFIDENT_UPPER:
            try:
                cb_prob = await _catboost_predict(url, client_features)
                final_prob = CASCADE_BERT_WEIGHT * bert_prob + (1 - CASCADE_BERT_WEIGHT) * cb_prob
                source = "cascade"
            except Exception as e:
                logger.warning(f"CatBoost falhou, usando BERT sozinho: {e}")
                final_prob = bert_prob
        else:
            final_prob = bert_prob

    # Decisao final
    is_phishing = final_prob > PHISHING_THRESHOLD
    confidence = (final_prob if is_phishing else 1.0 - final_prob) * 100

    label = "PHISHING" if is_phishing else "LEGITIMO"
    analysis = _build_analysis(is_phishing, confidence)

    inference_ms = (time.perf_counter() - start_time) * 1000

    return is_phishing, confidence, label, analysis, inference_ms, source


@app.get("/health")
async def health_check():
    """Endpoint de health check"""
    if model is None or tokenizer is None:
        raise HTTPException(status_code=503, detail="Modelo nao carregado")

    device = str(next(model.parameters()).device)

    return {
        "status": "healthy",
        "model_loaded": True,
        "cascade_enabled": catboost_model is not None,
        "device": device,
        "version": API_VERSION,
    }


def _build_analysis(is_phishing: bool, confidence: float) -> str:
    """Build analysis text for a prediction result. confidence is 0-100."""
    if is_phishing:
        if confidence >= 90:
            return f"URL classificada como PHISHING com alta confianca ({confidence:.1f}%). DomURLs-BERT identificou padroes fortemente suspeitos."
        elif confidence >= 70:
            return f"URL classificada como PHISHING ({confidence:.1f}%). DomURLs-BERT detectou caracteristicas suspeitas."
        else:
            return f"URL classificada como PHISHING com baixa confianca ({confidence:.1f}%). Recomenda-se cautela."
    else:
        if confidence >= 90:
            return f"URL classificada como LEGITIMA com alta confianca ({confidence:.1f}%)."
        elif confidence >= 70:
            return f"URL classificada como LEGITIMA ({confidence:.1f}%)."
        else:
            return f"URL classificada como LEGITIMA com baixa confianca ({confidence:.1f}%). Recomenda-se cautela."


async def predict_batch_phishing(
    requests: List[PhishingRequest],
) -> List[tuple]:
    """
    Batch prediction using cascata: BERT batch primeiro, CatBoost para incertos.

    Returns:
        List of (is_phishing, confidence, label, analysis, inference_ms, source) tuples.
    """
    import asyncio

    start_time = time.perf_counter()

    # Estagio 1: BERT batch
    feature_texts = [req.url for req in requests]

    inputs = tokenizer(
        feature_texts,
        return_tensors="pt",
        truncation=True,
        max_length=128,
        padding=True,
    )

    device = next(model.parameters()).device
    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = model(**inputs)
        probabilities = torch.softmax(outputs.logits, dim=-1)

    # Estagio 2: CatBoost para incertos (se disponivel)
    bert_probs = [probabilities[i][1].item() for i in range(len(requests))]
    final_probs = list(bert_probs)
    sources = ["bert"] * len(requests)

    if catboost_model is not None:
        uncertain_indices = [
            i for i, p in enumerate(bert_probs)
            if BERT_CONFIDENT_LOWER < p < BERT_CONFIDENT_UPPER
        ]
        if uncertain_indices:
            cb_tasks = [
                _catboost_predict(requests[i].url, requests[i].client_features)
                for i in uncertain_indices
            ]
            cb_results = await asyncio.gather(*cb_tasks, return_exceptions=True)
            for idx, cb_result in zip(uncertain_indices, cb_results):
                if isinstance(cb_result, Exception):
                    logger.warning(f"CatBoost falhou para {requests[idx].url}: {cb_result}")
                    continue
                final_probs[idx] = CASCADE_BERT_WEIGHT * bert_probs[idx] + (1 - CASCADE_BERT_WEIGHT) * cb_result
                sources[idx] = "cascade"

    inference_ms = (time.perf_counter() - start_time) * 1000

    results = []
    for i in range(len(requests)):
        is_phishing = final_probs[i] > PHISHING_THRESHOLD
        confidence = (final_probs[i] if is_phishing else 1.0 - final_probs[i]) * 100
        label = "PHISHING" if is_phishing else "LEGITIMO"
        analysis = _build_analysis(is_phishing, confidence)
        results.append((is_phishing, confidence, label, analysis, round(inference_ms, 2), sources[i]))

    return results


@app.post("/predict-batch", response_model=List[PhishingResponse])
async def predict_batch(requests: List[PhishingRequest]):
    """
    Batch prediction endpoint.
    Accepts array of PhishingRequest and returns array of PhishingResponse in same order.
    """
    if model is None or tokenizer is None:
        raise HTTPException(status_code=503, detail="Modelo nao carregado")

    if not requests:
        return []

    try:
        results = await predict_batch_phishing(requests)

        responses = []
        for req, (is_phishing, confidence, label, analysis, inference_ms, source) in zip(requests, results):
            responses.append(PhishingResponse(
                url=req.url,
                is_phishing=is_phishing,
                confidence=confidence,
                label=label,
                analysis=analysis,
                inference_ms=inference_ms,
                source=source,
            ))

        logger.info(
            f"Batch predicao: {len(requests)} URLs | "
            f"Inferencia total: {results[0][4]:.1f}ms"
        )

        return responses

    except Exception as e:
        logger.error(f"Erro na predicao batch: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro na predicao batch: {str(e)}")


@app.post("/predict", response_model=PhishingResponse)
async def predict(request: PhishingRequest):
    """
    Endpoint principal para deteccao de phishing.
    Recebe URL + client_features e retorna predicao do DomURLs-BERT.
    """
    if model is None or tokenizer is None:
        raise HTTPException(status_code=503, detail="Modelo nao carregado")

    try:
        is_phishing, confidence, label, analysis, inference_ms, source = await predict_phishing(
            request.url, request.client_features, request.mode
        )

        response = PhishingResponse(
            url=request.url,
            is_phishing=is_phishing,
            confidence=confidence,
            label=label,
            analysis=analysis,
            inference_ms=round(inference_ms, 2),
            source=source,
        )

        logger.info(
            f"Predicao: {label} ({confidence:.1f}%) | URL: {request.url} | "
            f"Inferencia: {inference_ms:.1f}ms | Source: {source}"
        )

        return response

    except Exception as e:
        logger.error(f"Erro na predicao: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro na predicao: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
