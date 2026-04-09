import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer, MarianMTModel, MarianTokenizer
from langdetect import detect as langdetect_detect
import logging
import os
from pathlib import Path
from auth import get_org_id

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Versao da API
API_VERSION = "4.0.0"

# Threshold de phishing — probabilidade minima para classificar como phishing.
# Valor mais alto reduz falsos positivos (sites legitimos marcados como phishing).
PHISHING_THRESHOLD = 0.65

# Cascata: limites de confianca do BERT para decidir sozinho.
# Fora dessa faixa, BERT decide direto. Dentro, aciona o CatBoost (estagio 2).
BERT_CONFIDENT_UPPER = 0.85  # P(phish) >= 0.85 → phishing direto
BERT_CONFIDENT_LOWER = 0.15  # P(phish) <= 0.15 → legitimo direto

# Peso do BERT na combinacao cascata (1-alpha = peso do CatBoost)
CASCADE_BERT_WEIGHT = 0.6

# Thresholds para classificacao de email
EMAIL_PHISHING_THRESHOLD = 0.7
EMAIL_SUSPICIOUS_THRESHOLD = 0.4
EMAIL_WEIGHT = 0.6
# Cap for email-only score when no phishing URLs confirm the verdict.
# The DistilBERT model is overconfident for many legitimate commercial emails,
# so without URL evidence we limit the score to SUSPICIOUS at most.
EMAIL_ONLY_CAP = 0.65

# Threshold mais alto para URLs dentro de emails.
# URLs em emails frequentemente sao tracking/redirect (ex: t1.em.linkedin.com/r/?id=...)
# que parecem phishing para o modelo mas sao legitimas.
EMAIL_URL_PHISHING_THRESHOLD = 0.90

# Dominios raiz conhecidos de servicos de email/tracking legitimos.
# URLs cujo dominio raiz pertence a esta lista sao consideradas legitimas
# sem passar pelo modelo BERT (evita falsos positivos de tracking URLs).
KNOWN_EMAIL_DOMAINS = {
    "linkedin.com", "google.com", "gmail.com", "youtube.com",
    "microsoft.com", "outlook.com", "live.com", "office.com",
    "apple.com", "icloud.com",
    "facebook.com", "instagram.com", "whatsapp.com", "meta.com",
    "twitter.com", "x.com",
    "amazon.com", "amazonaws.com",
    "github.com", "gitlab.com", "bitbucket.org",
    "slack.com", "notion.so", "figma.com", "canva.com",
    "zoom.us", "teams.microsoft.com",
    "netflix.com", "spotify.com", "discord.com",
    "stripe.com", "paypal.com",
    "mailchimp.com", "sendgrid.net", "mailgun.com",
    "hubspot.com", "salesforce.com",
    "claude.ai", "anthropic.com", "openai.com",
    "gov.br", "edu.br", "org.br",
}

# Sufixos de segundo nivel (SLDs) brasileiros — tratados como TLD para extracao de dominio.
# Ex: "auditar.med.br" tem raiz "auditar.med.br", nao "med.br".
BR_SLDS = {"com", "org", "net", "edu", "gov", "mil", "art", "coop", "emp", "med",
           "mus", "srv", "tur", "eco", "adm", "adv", "agr", "arq", "bio", "blog",
           "bmd", "eng", "esp", "etc", "far", "flog", "fnd", "fot", "fst", "ggf",
           "imb", "ind", "inf", "jor", "lel", "mat", "not", "ntr", "odo", "ppg",
           "pro", "psc", "qsl", "rec", "slg", "tmp", "trd", "vet", "vlog", "wiki"}

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
    from db import init_db, close_db
    await init_db()
    yield
    await close_db()


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


class EventCreateRequest(BaseModel):
    """Modelo de entrada para persistir um evento de analise de phishing"""
    event_type: str = Field(..., description="Tipo do evento: 'url' ou 'email'")
    is_phishing: bool = Field(..., description="Resultado da analise")
    confidence: float = Field(..., description="Confianca da predicao (0-100)")
    label: str = Field(..., description="Label: PHISHING, LEGITIMO ou SUSPICIOUS")
    url: Optional[str] = Field(default=None, description="URL analisada (para event_type='url')")
    email_subject: Optional[str] = Field(default=None, description="Assunto do email (para event_type='email')")
    email_sender: Optional[str] = Field(default=None, description="Remetente do email")
    analysis: Optional[str] = Field(default=None, description="Texto descritivo da analise")
    inference_ms: Optional[float] = Field(default=None, description="Tempo de inferencia em ms")
    source: Optional[str] = Field(default=None, description="Estagio que decidiu: bert, cascade, catboost")
    email_score: Optional[float] = Field(default=None, description="Score bruto do modelo de email (0-100)")
    language_detected: Optional[str] = Field(default=None, description="Idioma detectado")
    translated: Optional[bool] = Field(default=None, description="Se houve traducao")
    extension_id: Optional[str] = Field(default=None, description="ID da extensao que enviou o evento")
    user_agent: Optional[str] = Field(default=None, description="User-Agent do cliente")


class EventCreateResponse(BaseModel):
    """Modelo de resposta apos persistir um evento"""
    id: int = Field(..., description="ID unico do evento persistido")
    org_id: Optional[str] = Field(default=None, description="org_id da organizacao (None se anonimo)")
    event_type: str
    is_phishing: bool
    confidence: float
    label: str
    url: Optional[str] = None
    email_subject: Optional[str] = None
    email_sender: Optional[str] = None
    analysis: Optional[str] = None
    inference_ms: Optional[float] = None
    source: Optional[str] = None
    email_score: Optional[float] = None
    language_detected: Optional[str] = None
    translated: Optional[bool] = None
    extension_id: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: str = Field(..., description="Timestamp ISO 8601 da criacao do evento")


class OrgCreateRequest(BaseModel):
    """Modelo de entrada para criacao de organizacao"""
    org_id: str = Field(..., description="Identificador unico da organizacao (ex: acme-corp)")
    name: Optional[str] = Field(default=None, description="Nome legivel da organizacao")


class OrgCreateResponse(BaseModel):
    """Modelo de resposta para criacao de organizacao"""
    org_id: str = Field(..., description="Identificador da organizacao")
    api_key: str = Field(..., description="API Key gerada para autenticacao")
    name: Optional[str] = Field(default=None, description="Nome da organizacao")


class OrgSummaryResponse(BaseModel):
    """Modelo de resposta do resumo de eventos de uma organizacao"""
    org_id: str = Field(..., description="Identificador da organizacao")
    total_events: int = Field(..., description="Total de eventos registrados")
    phishing_count: int = Field(..., description="Eventos classificados como phishing")
    legitimate_count: int = Field(..., description="Eventos classificados como legitimos")
    url_count: int = Field(..., description="Eventos do tipo URL")
    email_count: int = Field(..., description="Eventos do tipo email")
    avg_confidence: Optional[float] = Field(default=None, description="Confianca media das predicoes (0-100)")
    last_event_at: Optional[str] = Field(default=None, description="Timestamp ISO 8601 do evento mais recente")


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


def _extract_root_domain(url: str) -> str:
    """Extrai dominio raiz de uma URL (ex: 't1.em.linkedin.com' -> 'linkedin.com').

    Trata SLDs brasileiros: 'fluxos.auditar.med.br' -> 'auditar.med.br'
    """
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or ""
        parts = hostname.lower().split(".")
        # Dominios brasileiros com SLD (ex: .com.br, .med.br): pega 3 partes como raiz
        if len(parts) >= 4 and parts[-1] == "br" and parts[-2] in BR_SLDS:
            return ".".join(parts[-3:])
        # Dominios .br simples (ex: exemplo.br)
        if len(parts) >= 3 and parts[-1] == "br":
            return ".".join(parts[-2:])
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return hostname
    except Exception:
        return ""


def _analyze_email_urls(urls: List[str]) -> List[EmailUrlResult]:
    """Analisa URLs encontradas no corpo do email usando BERT + whitelist de dominios conhecidos."""
    results = []
    for url in urls[:10]:
        root_domain = _extract_root_domain(url)

        # Dominios conhecidos de servicos legitimos sao isentos do modelo
        if root_domain in KNOWN_EMAIL_DOMAINS:
            results.append(EmailUrlResult(
                url=url, is_phishing=False, confidence=95.0, label="LEGITIMO",
            ))
            continue

        prob = _bert_predict(url)
        # Threshold mais alto para URLs em emails (tracking URLs geram falsos positivos)
        is_phishing = prob > EMAIL_URL_PHISHING_THRESHOLD
        confidence = (prob if is_phishing else 1.0 - prob) * 100
        label = "PHISHING" if is_phishing else "LEGITIMO"
        results.append(EmailUrlResult(
            url=url,
            is_phishing=is_phishing,
            confidence=round(confidence, 2),
            label=label,
        ))
    return results


def _build_email_analysis(label: str, confidence: float, email_score: float,
                          url_results: List[EmailUrlResult], language_detected: str,
                          translated: bool) -> str:
    """Gera texto de analise legivel para resultado de email."""
    parts = []

    if label == "PHISHING":
        parts.append(f"Email classificado como PHISHING com confianca de {confidence:.1f}%.")
    elif label == "SUSPICIOUS":
        parts.append(f"Email classificado como SUSPICIOUS com confianca de {confidence:.1f}%. Recomenda-se cautela.")
    else:
        parts.append(f"Email classificado como LEGITIMO com confianca de {confidence:.1f}%.")

    parts.append(f"Score do conteudo do email: {email_score:.1f}%.")

    if url_results:
        phishing_urls = [r for r in url_results if r.is_phishing]
        if phishing_urls:
            parts.append(f"{len(phishing_urls)} de {len(url_results)} URLs detectadas como phishing.")
        else:
            parts.append(f"{len(url_results)} URLs analisadas, nenhuma suspeita.")

    if translated:
        parts.append(f"Idioma detectado: {language_detected}. Traduzido para EN antes da classificacao.")

    return " ".join(parts)


@app.post("/analyze-email", response_model=EmailResponse)
async def analyze_email(
    request: EmailRequest,
    org_id: Optional[str] = Depends(get_org_id),
):
    """Endpoint de analise de email phishing usando DistilBERT + analise de URLs.
    Persiste automaticamente o resultado no banco se disponivel.
    """
    if email_model is None:
        raise HTTPException(status_code=503, detail="Modelo de email nao carregado")

    start_time = time.perf_counter()

    # 1. Formata texto com headers de email (o modelo espera From:/Subject:)
    parts = []
    if request.sender:
        parts.append(f"From: {request.sender}")
    if request.subject:
        parts.append(f"Subject: {request.subject}")
    parts.append("")  # blank line before body
    parts.append(request.body)
    full_text = "\n".join(parts)

    # 2. Detecta idioma e traduz se necessario
    translated_text, language_detected, was_translated = detect_and_translate(full_text)

    # 3. Classifica com DistilBERT email
    device = next(email_model.parameters()).device
    inputs = email_tokenizer(
        translated_text,
        return_tensors="pt",
        truncation=True,
        max_length=512,
        padding=True,
    )
    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = email_model(**inputs)
        probabilities = torch.softmax(outputs.logits, dim=-1)

    email_prob = probabilities[0][1].item()
    email_score = email_prob * 100

    # 4. Analisa URLs do body
    url_results = []
    if request.urls_in_body and model is not None:
        url_results = _analyze_email_urls(request.urls_in_body)

    # 5. Combinacao de scores
    phishing_urls = [r for r in url_results if r.is_phishing]
    high_confidence_phishing = [r for r in phishing_urls if r.confidence > 80]

    if high_confidence_phishing:
        # URLs with high confidence confirm phishing
        final_prob = max(email_prob, 0.9)
    elif phishing_urls:
        # Some phishing URLs: weighted combination
        max_url_prob = max(r.confidence / 100 for r in phishing_urls)
        final_prob = EMAIL_WEIGHT * email_prob + (1 - EMAIL_WEIGHT) * max_url_prob
    else:
        # No phishing URLs: cap the email-only score.
        # The DistilBERT model is overconfident for legitimate commercial emails
        # (e.g. Google, LinkedIn, Netflix notifications score >95% phishing).
        # Without URL evidence, we limit the verdict to SUSPICIOUS at most.
        final_prob = min(email_prob, EMAIL_ONLY_CAP)

    # 6. Labels
    if final_prob > EMAIL_PHISHING_THRESHOLD:
        label = "PHISHING"
    elif final_prob >= EMAIL_SUSPICIOUS_THRESHOLD:
        label = "SUSPICIOUS"
    else:
        label = "LEGITIMO"

    is_phishing = final_prob > EMAIL_PHISHING_THRESHOLD
    confidence = (final_prob if is_phishing else 1.0 - final_prob) * 100

    inference_ms = (time.perf_counter() - start_time) * 1000

    analysis = _build_email_analysis(label, confidence, email_score, url_results,
                                     language_detected, was_translated)

    # Auto-persist: fire-and-forget, never block or fail the response
    from db import DB_ENABLED, log_event
    if DB_ENABLED:
        try:
            row = await log_event(
                org_id=org_id,
                event_type="email",
                is_phishing=is_phishing,
                confidence=round(confidence, 2),
                label=label,
                email_subject=request.subject,
                email_sender=request.sender,
                analysis=analysis,
                inference_ms=round(inference_ms, 2),
                email_score=round(email_score, 2),
                language_detected=language_detected,
                translated=was_translated,
            )
            if is_phishing and org_id:
                import asyncio
                from alerts import send_webhook_alert
                asyncio.ensure_future(send_webhook_alert(org_id=org_id, event=row))
        except Exception as db_exc:
            logger.warning(f"Auto-persist falhou (analyze-email): {db_exc}")

    return EmailResponse(
        is_phishing=is_phishing,
        confidence=round(confidence, 2),
        label=label,
        analysis=analysis,
        inference_ms=round(inference_ms, 2),
        email_score=round(email_score, 2),
        url_results=url_results,
        language_detected=language_detected,
        translated=was_translated,
    )


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
        "email_model_loaded": email_model is not None,
        "device": device,
        "version": API_VERSION,
    }


@app.post("/admin/orgs", response_model=OrgCreateResponse, status_code=201)
async def create_organization(request: OrgCreateRequest):
    """Cria uma nova organizacao e retorna sua API Key.

    Este endpoint deve ser protegido por rede/firewall em producao.
    Nao requer autenticacao para facilitar o bootstrap inicial.
    """
    from auth import create_org
    from db import DB_ENABLED

    if not DB_ENABLED:
        raise HTTPException(status_code=503, detail="Database nao disponivel")

    try:
        api_key = await create_org(org_id=request.org_id, name=request.name)
    except Exception as exc:
        # IntegrityError when org_id already exists
        error_msg = str(exc)
        if "unique" in error_msg.lower() or "duplicate" in error_msg.lower():
            raise HTTPException(status_code=409, detail=f"org_id '{request.org_id}' ja existe")
        raise HTTPException(status_code=500, detail=f"Erro ao criar organizacao: {error_msg}")

    return OrgCreateResponse(org_id=request.org_id, api_key=api_key, name=request.name)


@app.get("/reports/{org_id}/summary", response_model=OrgSummaryResponse)
async def get_org_summary_endpoint(
    org_id: str,
    caller_org_id: Optional[str] = Depends(get_org_id),
):
    """Retorna um resumo agregado dos eventos de phishing de uma organizacao.

    Requer autenticacao via X-API-Key. Apenas a propria organizacao pode
    acessar seu resumo (caller org_id deve ser igual ao org_id do path).
    """
    from db import DB_ENABLED, get_org_summary

    if not DB_ENABLED:
        raise HTTPException(status_code=503, detail="Database nao disponivel")

    if caller_org_id is None:
        raise HTTPException(status_code=401, detail="Autenticacao obrigatoria para este endpoint")

    if caller_org_id != org_id:
        raise HTTPException(status_code=403, detail="Acesso negado: voce so pode acessar o resumo da sua propria organizacao")

    try:
        summary = await get_org_summary(org_id=org_id)
    except Exception as exc:
        logger.error(f"Erro ao buscar resumo da organizacao: {exc}")
        raise HTTPException(status_code=500, detail=f"Erro ao buscar resumo: {exc}")

    last_event_at = summary["last_event_at"]
    if last_event_at is not None and hasattr(last_event_at, "isoformat"):
        last_event_at = last_event_at.isoformat()
    elif last_event_at is not None:
        last_event_at = str(last_event_at)

    return OrgSummaryResponse(
        org_id=summary["org_id"],
        total_events=summary["total_events"],
        phishing_count=summary["phishing_count"],
        legitimate_count=summary["legitimate_count"],
        url_count=summary["url_count"],
        email_count=summary["email_count"],
        avg_confidence=summary["avg_confidence"],
        last_event_at=last_event_at,
    )


@app.post("/events", response_model=EventCreateResponse, status_code=201)
async def create_event(
    request: EventCreateRequest,
    org_id: Optional[str] = Depends(get_org_id),
):
    """Persiste um evento de analise de phishing no banco de dados.

    Requer X-API-Key para associar o evento a uma organizacao.
    Requisicoes anonimas (sem X-API-Key) sao aceitas mas ficam sem org_id.
    """
    from db import DB_ENABLED, log_event

    if not DB_ENABLED:
        raise HTTPException(status_code=503, detail="Database nao disponivel")

    if request.event_type not in ("url", "email"):
        raise HTTPException(status_code=422, detail="event_type deve ser 'url' ou 'email'")

    try:
        row = await log_event(
            org_id=org_id,
            event_type=request.event_type,
            is_phishing=request.is_phishing,
            confidence=request.confidence,
            label=request.label,
            url=request.url,
            email_subject=request.email_subject,
            email_sender=request.email_sender,
            analysis=request.analysis,
            inference_ms=request.inference_ms,
            source=request.source,
            email_score=request.email_score,
            language_detected=request.language_detected,
            translated=request.translated,
            extension_id=request.extension_id,
            user_agent=request.user_agent,
        )
    except Exception as exc:
        logger.error(f"Erro ao persistir evento: {exc}")
        raise HTTPException(status_code=500, detail=f"Erro ao persistir evento: {exc}")

    created_at = row["created_at"]
    created_at_str = created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at)

    return EventCreateResponse(
        id=row["id"],
        org_id=row["org_id"],
        event_type=row["event_type"],
        is_phishing=row["is_phishing"],
        confidence=row["confidence"],
        label=row["label"],
        url=row["url"],
        email_subject=row["email_subject"],
        email_sender=row["email_sender"],
        analysis=row["analysis"],
        inference_ms=row["inference_ms"],
        source=row["source"],
        email_score=row["email_score"],
        language_detected=row["language_detected"],
        translated=row["translated"],
        extension_id=row["extension_id"],
        user_agent=row["user_agent"],
        created_at=created_at_str,
    )


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
async def predict_batch(
    requests: List[PhishingRequest],
    org_id: Optional[str] = Depends(get_org_id),
):
    """
    Batch prediction endpoint.
    Accepts array of PhishingRequest and returns array of PhishingResponse in same order.
    Persiste automaticamente cada resultado no banco se disponivel.
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

        # Auto-persist: fire-and-forget for each item in batch
        import asyncio
        from db import DB_ENABLED, log_event
        if DB_ENABLED:
            async def _persist_batch():
                from alerts import send_webhook_alert
                for req, (is_phishing, confidence, label, analysis, inference_ms, source) in zip(requests, results):
                    try:
                        row = await log_event(
                            org_id=org_id,
                            event_type="url",
                            is_phishing=is_phishing,
                            confidence=round(confidence, 2),
                            label=label,
                            url=req.url,
                            analysis=analysis,
                            inference_ms=round(inference_ms, 2),
                            source=source,
                        )
                        if is_phishing and org_id:
                            await send_webhook_alert(org_id=org_id, event=row)
                    except Exception as db_exc:
                        logger.warning(f"Auto-persist falhou (predict-batch) para {req.url}: {db_exc}")
            asyncio.ensure_future(_persist_batch())

        return responses

    except Exception as e:
        logger.error(f"Erro na predicao batch: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro na predicao batch: {str(e)}")


@app.post("/predict", response_model=PhishingResponse)
async def predict(
    request: PhishingRequest,
    org_id: Optional[str] = Depends(get_org_id),
):
    """
    Endpoint principal para deteccao de phishing.
    Recebe URL + client_features e retorna predicao do DomURLs-BERT.
    Persiste automaticamente o resultado no banco se disponivel.
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

        # Auto-persist: fire-and-forget, never block or fail the response
        from db import DB_ENABLED, log_event
        if DB_ENABLED:
            try:
                row = await log_event(
                    org_id=org_id,
                    event_type="url",
                    is_phishing=is_phishing,
                    confidence=round(confidence, 2),
                    label=label,
                    url=request.url,
                    analysis=analysis,
                    inference_ms=round(inference_ms, 2),
                    source=source,
                )
                if is_phishing and org_id:
                    import asyncio
                    from alerts import send_webhook_alert
                    asyncio.ensure_future(send_webhook_alert(org_id=org_id, event=row))
            except Exception as db_exc:
                logger.warning(f"Auto-persist falhou (predict): {db_exc}")

        return response

    except Exception as e:
        logger.error(f"Erro na predicao: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro na predicao: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
