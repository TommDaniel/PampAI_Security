"""
Tests for Phishing Detection API - DomURLs-BERT
Uses pytest with FastAPI TestClient (mocked model).
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient
import torch


# Mock model before importing app
def _create_mock_model():
    """Creates a mock model with proper .parameters() returning CPU device."""
    mock_model = MagicMock()
    mock_model.parameters.side_effect = lambda: iter([torch.tensor([1.0])])  # CPU device, fresh iterator each call
    mock_model.eval.return_value = None
    return mock_model


def _create_mock_tokenizer():
    """Creates a mock tokenizer returning dummy input_ids and attention_mask."""
    mock_tokenizer = MagicMock()
    mock_tokenizer.return_value = {
        "input_ids": torch.tensor([[101, 102]]),
        "attention_mask": torch.tensor([[1, 1]]),
    }
    return mock_tokenizer


def _mock_load_model():
    """Patches load_model to avoid loading the real 422MB model in tests."""
    import app as app_module

    app_module.model = _create_mock_model()
    app_module.tokenizer = _create_mock_tokenizer()

    # Also mock email model and tokenizer
    app_module.email_model = _create_mock_model()
    app_module.email_tokenizer = _create_mock_tokenizer()

    # Translation model not loaded by default (tests can override)
    app_module.translation_model = None
    app_module.translation_tokenizer = None


def _set_model_output(logits_values: list):
    """Helper to set what the mock model returns."""
    import app as app_module

    mock_output = MagicMock()
    mock_output.logits = torch.tensor([logits_values])
    app_module.model.__call__ = MagicMock(return_value=mock_output)
    app_module.model.return_value = mock_output


# Patch load_model and extract_server_features before creating TestClient
_mock_server_features = AsyncMock()

with patch("app.load_model", _mock_load_model), \
     patch("server_features.extract_server_features", _mock_server_features):
    from app import app
    from server_features import ServerFeatures

    _mock_load_model()
    # Default: return empty ServerFeatures (all defaults -1)
    _mock_server_features.return_value = ServerFeatures()
    client = TestClient(app)


SAMPLE_REQUEST = {
    "url": "https://google.com",
    "client_features": {
        "length": 25,
        "dom_length": 10,
        "dot": 2,
        "hyphen": 0,
        "slash": 3,
        "at": 0,
        "params": 0,
        "shortened": 0,
        "tls": 1,
        "vowels_domain": 3,
        "email": 0,
    },
}

PHISHING_REQUEST = {
    "url": "http://192.168.1.1.suspicious-login-verify.com/@phishing",
    "client_features": {
        "length": 150,
        "dom_length": 45,
        "dot": 8,
        "hyphen": 3,
        "slash": 5,
        "at": 1,
        "params": 2,
        "shortened": 0,
        "tls": 0,
        "vowels_domain": 8,
        "email": 0,
    },
}


class TestHealthEndpoint:
    def test_health_returns_200(self):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_response_fields(self):
        response = client.get("/health")
        data = response.json()
        assert data["status"] == "healthy"
        assert data["model_loaded"] is True
        assert "device" in data
        assert "version" in data


class TestPredictEndpoint:
    def test_predict_returns_200(self):
        _set_model_output([2.0, -2.0])
        response = client.post("/predict", json=SAMPLE_REQUEST)
        assert response.status_code == 200

    def test_predict_response_schema(self):
        _set_model_output([2.0, -2.0])
        response = client.post("/predict", json=SAMPLE_REQUEST)
        data = response.json()

        assert "url" in data
        assert "is_phishing" in data
        assert "confidence" in data
        assert "label" in data
        assert "analysis" in data
        assert "inference_ms" in data

        # No RF fields
        assert "rf_confidence" not in data
        assert "model_used" not in data

    def test_predict_legitimate(self):
        _set_model_output([3.0, -3.0])
        response = client.post("/predict", json=SAMPLE_REQUEST)
        data = response.json()

        assert data["url"] == SAMPLE_REQUEST["url"]
        assert data["is_phishing"] is False
        assert data["label"] == "LEGITIMO"
        assert data["confidence"] > 90
        assert data["inference_ms"] >= 0

    def test_predict_phishing(self):
        _set_model_output([-3.0, 3.0])
        response = client.post("/predict", json=PHISHING_REQUEST)
        data = response.json()

        assert data["url"] == PHISHING_REQUEST["url"]
        assert data["is_phishing"] is True
        assert data["label"] == "PHISHING"
        assert data["confidence"] > 90
        assert data["inference_ms"] >= 0

    def test_predict_low_confidence(self):
        _set_model_output([0.1, -0.1])
        response = client.post("/predict", json=SAMPLE_REQUEST)
        data = response.json()

        assert data["confidence"] < 70
        assert "baixa confianca" in data["analysis"].lower() or "cautela" in data["analysis"].lower()

    def test_predict_missing_url_returns_422(self):
        response = client.post("/predict", json={"client_features": SAMPLE_REQUEST["client_features"]})
        assert response.status_code == 422

    def test_predict_missing_features_returns_422(self):
        response = client.post("/predict", json={"url": "https://example.com"})
        assert response.status_code == 422

    def test_predict_incomplete_features_returns_422(self):
        response = client.post("/predict", json={
            "url": "https://example.com",
            "client_features": {"length": 25},
        })
        assert response.status_code == 422


class TestCORS:
    def test_cors_headers_present(self):
        response = client.options(
            "/predict",
            headers={
                "Origin": "chrome-extension://abc123",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert response.status_code in (200, 204)


class TestNoRFLogic:
    """Verify all Random Forest logic has been removed."""

    def test_no_analyze_predictions_function(self):
        import app as app_module
        assert not hasattr(app_module, "analyze_predictions")

    def test_no_confidence_threshold(self):
        import app as app_module
        assert not hasattr(app_module, "CONFIDENCE_THRESHOLD")

    def test_no_sklearn_imports(self):
        import app as app_module
        source = open(app_module.__file__).read()
        assert "sklearn" not in source
        assert "RandomForest" not in source
        assert "rf_confidence" not in source
        assert "rf_prediction" not in source


class TestPredictBatchEndpoint:
    def test_batch_returns_200(self):
        _set_model_output([2.0, -2.0])
        # Mock for batch: model returns logits for N inputs
        import app as app_module
        mock_output = MagicMock()
        mock_output.logits = torch.tensor([[2.0, -2.0], [2.0, -2.0]])
        app_module.model.__call__ = MagicMock(return_value=mock_output)
        app_module.model.return_value = mock_output

        response = client.post("/predict-batch", json=[SAMPLE_REQUEST, SAMPLE_REQUEST])
        assert response.status_code == 200

    def test_batch_returns_correct_count(self):
        import app as app_module
        mock_output = MagicMock()
        mock_output.logits = torch.tensor([[2.0, -2.0], [-2.0, 2.0], [2.0, -2.0]])
        app_module.model.__call__ = MagicMock(return_value=mock_output)
        app_module.model.return_value = mock_output

        batch = [SAMPLE_REQUEST, PHISHING_REQUEST, SAMPLE_REQUEST]
        response = client.post("/predict-batch", json=batch)
        data = response.json()
        assert len(data) == 3

    def test_batch_preserves_order(self):
        import app as app_module
        # First legitimate, second phishing
        mock_output = MagicMock()
        mock_output.logits = torch.tensor([[3.0, -3.0], [-3.0, 3.0]])
        app_module.model.__call__ = MagicMock(return_value=mock_output)
        app_module.model.return_value = mock_output

        batch = [SAMPLE_REQUEST, PHISHING_REQUEST]
        response = client.post("/predict-batch", json=batch)
        data = response.json()

        assert data[0]["url"] == SAMPLE_REQUEST["url"]
        assert data[0]["is_phishing"] is False
        assert data[0]["label"] == "LEGITIMO"

        assert data[1]["url"] == PHISHING_REQUEST["url"]
        assert data[1]["is_phishing"] is True
        assert data[1]["label"] == "PHISHING"

    def test_batch_response_schema(self):
        import app as app_module
        mock_output = MagicMock()
        mock_output.logits = torch.tensor([[2.0, -2.0]])
        app_module.model.__call__ = MagicMock(return_value=mock_output)
        app_module.model.return_value = mock_output

        response = client.post("/predict-batch", json=[SAMPLE_REQUEST])
        data = response.json()
        item = data[0]

        assert "url" in item
        assert "is_phishing" in item
        assert "confidence" in item
        assert "label" in item
        assert "analysis" in item
        assert "inference_ms" in item

    def test_batch_five_urls(self):
        """Acceptance criteria: batch of 5 URLs works correctly."""
        import app as app_module
        mock_output = MagicMock()
        # 5 URLs: 3 legit, 2 phishing
        mock_output.logits = torch.tensor([
            [3.0, -3.0],  # legit
            [-3.0, 3.0],  # phishing
            [3.0, -3.0],  # legit
            [-3.0, 3.0],  # phishing
            [3.0, -3.0],  # legit
        ])
        app_module.model.__call__ = MagicMock(return_value=mock_output)
        app_module.model.return_value = mock_output

        batch = [SAMPLE_REQUEST] * 3 + [PHISHING_REQUEST] * 2
        # Fix URLs to be unique for clarity
        batch_with_urls = []
        for i, req in enumerate(batch):
            r = dict(req)
            r["url"] = f"https://test{i}.com"
            batch_with_urls.append(r)

        response = client.post("/predict-batch", json=batch_with_urls)
        data = response.json()

        assert len(data) == 5
        assert data[0]["is_phishing"] is False
        assert data[1]["is_phishing"] is True
        assert data[2]["is_phishing"] is False
        assert data[3]["is_phishing"] is True
        assert data[4]["is_phishing"] is False

    def test_batch_empty_returns_empty(self):
        response = client.post("/predict-batch", json=[])
        assert response.status_code == 200
        assert response.json() == []

    def test_batch_invalid_request_returns_422(self):
        response = client.post("/predict-batch", json=[{"url": "https://test.com"}])
        assert response.status_code == 422


class TestTokenizerConfig:
    """Validate tokenizer configuration."""

    def test_tokenizer_max_length_is_128(self):
        """URL tokenizer max_length must be 128 to match training."""
        import app as app_module
        source = open(app_module.__file__).read()
        assert "max_length=128" in source


class TestServerFeatures:
    """Tests for server_features.py module."""

    def test_extract_domain_basic(self):
        from server_features import _extract_domain
        assert _extract_domain("https://www.google.com/path") == "google.com"
        assert _extract_domain("http://example.org") == "example.org"
        assert _extract_domain("https://sub.domain.co.uk/page") == "sub.domain.co.uk"

    def test_extract_domain_no_www(self):
        from server_features import _extract_domain
        assert _extract_domain("https://www.test.com") == "test.com"

    def test_extract_domain_ip(self):
        from server_features import _extract_domain
        assert _extract_domain("http://192.168.1.1/login") == "192.168.1.1"

    def test_extract_domain_empty(self):
        from server_features import _extract_domain
        assert _extract_domain("") == ""

    def test_build_whois_text_found(self):
        from server_features import _build_whois_text
        data = {
            "status": "found",
            "domain_age_days": 365,
            "registrar": "GoDaddy",
            "days_to_expire": 250,
        }
        text = _build_whois_text(data)
        assert text == "[AGE] 365d [REG] GoDaddy [EXPIRE] 250d [WHOIS] found"

    def test_build_whois_text_not_found(self):
        from server_features import _build_whois_text
        assert _build_whois_text({}) == "[WHOIS] unknown"
        assert _build_whois_text({"status": "not_found"}) == "[WHOIS] unknown"

    def test_build_whois_text_partial(self):
        from server_features import _build_whois_text
        data = {"status": "found", "registrar": "Namecheap"}
        text = _build_whois_text(data)
        assert text == "[AGE] ?d [REG] Namecheap [EXPIRE] ?d [WHOIS] found"

    def test_build_whois_text_registrar_truncated(self):
        from server_features import _build_whois_text
        data = {
            "status": "found",
            "registrar": "A Very Long Registrar Name That Exceeds 25 Characters",
            "domain_age_days": 100,
            "days_to_expire": 200,
        }
        text = _build_whois_text(data)
        # Registrar is truncated to 25 chars
        reg_part = text.split("[REG] ")[1].split(" [EXPIRE]")[0]
        assert len(reg_part) <= 25
        assert reg_part == "A Very Long Registrar Nam"

    def test_server_features_defaults(self):
        sf = ServerFeatures()
        assert sf.redirects == -1
        assert sf.dom_age == -1
        assert sf.dom_expire == -1
        assert sf.mx_servers == -1
        assert sf.nameservers == -1
        assert sf.dom_spf == -1
        assert sf.dom_in_ip == -1
        assert sf.srv_client == -1
        assert sf.domain_google_index == -1
        assert sf.whois_text == "[WHOIS] unknown"

    def test_whois_cache_lookup(self):
        """Test that WHOIS cache returns data for known domains."""
        import asyncio
        from server_features import _lookup_whois_cached, _load_whois_cache

        # Force load cache
        cache = _load_whois_cache()
        if cache:
            # Get first domain with status=found
            found_domain = None
            for domain, data in cache.items():
                if data.get("status") == "found":
                    found_domain = domain
                    break

            if found_domain:
                result = asyncio.run(
                    _lookup_whois_cached(found_domain)
                )
                assert result.get("status") == "found"

    def test_whois_cache_miss(self):
        """Test that WHOIS cache returns empty for unknown domains."""
        import asyncio
        from server_features import _lookup_whois_cached

        result = asyncio.run(
            _lookup_whois_cached("definitely-not-in-cache-xyz123.com")
        )
        assert result == {}

    def test_extract_server_features_returns_dataclass(self):
        """Test that extract_server_features returns ServerFeatures."""
        import asyncio
        from server_features import extract_server_features

        # Will use cache (no network), DNS/redirects will fail gracefully
        result = asyncio.run(
            extract_server_features("https://example.com")
        )
        assert isinstance(result, ServerFeatures)
        assert result.domain_google_index == -1  # always -1

    def test_extract_server_features_empty_url(self):
        """Empty URL returns all defaults."""
        import asyncio
        from server_features import extract_server_features

        result = asyncio.run(
            extract_server_features("")
        )
        assert result.whois_text == "[WHOIS] unknown"
        assert result.redirects == -1

    def test_individual_lookup_failure_does_not_block(self):
        """If one lookup fails, others still return results."""
        import asyncio
        from server_features import extract_server_features, _load_whois_cache

        cache = _load_whois_cache()
        found_domain = None
        for domain, data in cache.items():
            if data.get("status") == "found":
                found_domain = domain
                break

        if found_domain:
            result = asyncio.run(
                extract_server_features(f"https://{found_domain}")
            )
            # WHOIS from cache should work even if DNS/redirects fail
            assert "found" in result.whois_text
            assert result.dom_age != -1 or result.dom_expire != -1


# ==================================================================
# Email Analysis Endpoint Tests (US-007)
# ==================================================================

def _set_email_model_output(logits_values: list):
    """Helper to set what the mock email model returns."""
    import app as app_module

    mock_output = MagicMock()
    mock_output.logits = torch.tensor([logits_values])
    app_module.email_model.__call__ = MagicMock(return_value=mock_output)
    app_module.email_model.return_value = mock_output


PHISHING_EMAIL = {
    "subject": "URGENT: Your account has been compromised",
    "body": "Dear customer, your account has been compromised. Click here immediately to verify your identity and restore access. Failure to do so within 24 hours will result in permanent account closure.",
    "sender": "security@fake-bank-alert.com",
    "urls_in_body": ["http://fake-bank-alert.com/verify"],
}

LEGIT_EMAIL = {
    "subject": "Meeting reminder",
    "body": "Hi team, just a reminder that our weekly standup is tomorrow at 10am. Please prepare your updates.",
    "sender": "manager@company.com",
    "urls_in_body": [],
}

PORTUGUESE_EMAIL = {
    "subject": "Lembrete de reuniao",
    "body": "Ola equipe, apenas um lembrete de que nossa reuniao semanal e amanha as 10h.",
    "sender": "gerente@empresa.com.br",
    "urls_in_body": [],
}

EMAIL_WITH_URLS = {
    "subject": "Check this out",
    "body": "Click the link below to see the document.",
    "sender": "someone@example.com",
    "urls_in_body": ["https://suspicious-site.com/login", "https://google.com"],
}

EMPTY_EMAIL = {
    "subject": "",
    "body": "",
    "sender": "",
    "urls_in_body": [],
}


class TestEmailAnalyzeEndpoint:
    """Tests for POST /analyze-email endpoint."""

    def test_phishing_email_english(self):
        """Email phishing em ingles com URL phishing -> is_phishing: true, label: PHISHING."""
        # logits: [legit, phishing] — high phishing probability
        _set_email_model_output([-3.0, 3.0])
        _set_model_output([-3.0, 3.0])  # URL model also returns phishing
        response = client.post("/analyze-email", json=PHISHING_EMAIL)
        assert response.status_code == 200
        data = response.json()
        assert data["is_phishing"] is True
        assert data["label"] == "PHISHING"
        assert data["confidence"] > 80

    def test_legitimate_email(self):
        """Email legitimo -> is_phishing: false, label: LEGITIMO."""
        _set_email_model_output([3.0, -3.0])
        response = client.post("/analyze-email", json=LEGIT_EMAIL)
        assert response.status_code == 200
        data = response.json()
        assert data["is_phishing"] is False
        assert data["label"] == "LEGITIMO"

    def test_suspicious_email(self):
        """Email ambiguo -> label: SUSPICIOUS (score entre 40-60%)."""
        # logits that produce ~0.5 probability (within 0.4-0.6 range)
        _set_email_model_output([-0.2, 0.2])
        response = client.post("/analyze-email", json=LEGIT_EMAIL)
        assert response.status_code == 200
        data = response.json()
        assert data["label"] == "SUSPICIOUS"

    def test_portuguese_email_translation(self):
        """Email em portugues -> translated: true, language_detected: pt."""
        import app as app_module

        # Set up translation model mocks
        app_module.translation_model = _create_mock_model()
        app_module.translation_tokenizer = _create_mock_tokenizer()

        # Mock generate to return dummy translated tokens
        app_module.translation_model.generate = MagicMock(
            return_value=torch.tensor([[101, 102, 103]])
        )
        app_module.translation_tokenizer.decode = MagicMock(
            return_value="Hello team, just a reminder that our weekly meeting is tomorrow at 10am."
        )

        _set_email_model_output([3.0, -3.0])

        with patch("app.langdetect_detect", return_value="pt"):
            response = client.post("/analyze-email", json=PORTUGUESE_EMAIL)

        assert response.status_code == 200
        data = response.json()
        assert data["translated"] is True
        assert data["language_detected"] == "pt"

        # Cleanup
        app_module.translation_model = None
        app_module.translation_tokenizer = None

    def test_email_with_urls(self):
        """Email com URLs no body -> url_results preenchido."""
        # Email model: legitimate
        _set_email_model_output([3.0, -3.0])
        # URL model: set for BERT URL predictions
        _set_model_output([-2.0, 2.0])  # phishing URL

        response = client.post("/analyze-email", json=EMAIL_WITH_URLS)
        assert response.status_code == 200
        data = response.json()
        assert len(data["url_results"]) == 2
        for url_result in data["url_results"]:
            assert "url" in url_result
            assert "is_phishing" in url_result
            assert "confidence" in url_result
            assert "label" in url_result

    def test_empty_body_email(self):
        """Email com body vazio -> resposta valida (sem erro)."""
        _set_email_model_output([2.0, -2.0])
        response = client.post("/analyze-email", json=EMPTY_EMAIL)
        assert response.status_code == 200
        data = response.json()
        assert "is_phishing" in data
        assert "label" in data
        assert "confidence" in data

    def test_email_response_schema(self):
        """Validate all EmailResponse fields are present."""
        _set_email_model_output([3.0, -3.0])
        response = client.post("/analyze-email", json=LEGIT_EMAIL)
        data = response.json()

        assert "is_phishing" in data
        assert "confidence" in data
        assert "label" in data
        assert "analysis" in data
        assert "inference_ms" in data
        assert "email_score" in data
        assert "url_results" in data
        assert "language_detected" in data
        assert "translated" in data

    def test_email_model_unavailable_returns_503(self):
        """POST /analyze-email returns 503 if email_model is None."""
        import app as app_module
        original = app_module.email_model
        app_module.email_model = None
        try:
            response = client.post("/analyze-email", json=LEGIT_EMAIL)
            assert response.status_code == 503
        finally:
            app_module.email_model = original

    def test_inference_ms_non_negative(self):
        """inference_ms must be >= 0."""
        _set_email_model_output([3.0, -3.0])
        data = client.post("/analyze-email", json=LEGIT_EMAIL).json()
        assert data["inference_ms"] >= 0

    def test_confidence_range(self):
        """Confidence must be 0-100."""
        _set_email_model_output([3.0, -3.0])
        data = client.post("/analyze-email", json=LEGIT_EMAIL).json()
        assert 0 <= data["confidence"] <= 100

    def test_email_score_range(self):
        """email_score must be 0-100."""
        _set_email_model_output([3.0, -3.0])
        data = client.post("/analyze-email", json=LEGIT_EMAIL).json()
        assert 0 <= data["email_score"] <= 100

    def test_analysis_text_non_empty(self):
        """Analysis text must be non-empty."""
        _set_email_model_output([3.0, -3.0])
        data = client.post("/analyze-email", json=LEGIT_EMAIL).json()
        assert len(data["analysis"]) > 0

    # ---------------------------------------------------------------------
    # False-positive reduction tests (gates de corroboracao URL+texto)
    # ---------------------------------------------------------------------

    def test_isolated_phishing_url_does_not_force_phishing(self):
        """1 URL phishing isolada entre 9 legitimas NAO deve forcar PHISHING.

        Antes: max(email_prob, 0.9) forcava PHISHING quando 1 URL tinha conf > 80.
        Agora: phish_ratio=0.1 cai no ramo 'isolated' capado em EMAIL_ONLY_CAP.
        """
        _set_email_model_output([3.0, -3.0])  # email benigno
        # 1 URL phishing (prob=0.95), 9 URLs legitimas (prob=0.05)
        def bert_side_effect(url):
            return 0.95 if "evil" in url else 0.05
        payload = {
            "subject": "Newsletter semanal",
            "body": "Confira as novidades desta semana.",
            "sender": "news@loja.test",
            "urls_in_body": [
                f"https://loja{i}.test/produto" for i in range(9)
            ] + ["https://evil-phish.test/login"],
        }
        with patch("app._bert_predict", side_effect=bert_side_effect):
            response = client.post("/analyze-email", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["label"] != "PHISHING", (
            f"Expected not PHISHING, got {data['label']} "
            f"conf={data['confidence']}"
        )

    def test_all_urls_phishing_keeps_phishing(self):
        """Todas as URLs phishing com alta confianca → gate 1 ativa → PHISHING.

        Regressao: garante que o relaxamento nao quebrou deteccao genuina.
        """
        _set_email_model_output([-1.0, 1.0])  # email suspeito (email_prob~0.73)
        payload = {
            "subject": "URGENT: verify your account",
            "body": "Click now to avoid suspension.",
            "sender": "security@fakebank.test",
            "urls_in_body": [
                "https://phish1.test/login",
                "https://phish2.test/verify",
                "https://phish3.test/update",
            ],
        }
        with patch("app._bert_predict", side_effect=lambda u: 0.95):
            response = client.post("/analyze-email", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["label"] == "PHISHING"
        assert data["is_phishing"] is True

    def test_email_only_overconfident_capped_at_suspicious(self):
        """Texto overconfident sozinho (sem URLs) nunca vira PHISHING.

        DistilBERT erra em emails comerciais com palavras-gatilho; o cap
        EMAIL_ONLY_CAP=0.60 garante que o veredicto final fica <= SUSPICIOUS.
        """
        _set_email_model_output([-5.0, 5.0])  # email_prob ~= 0.9933
        payload = {
            "subject": "CLIQUE AQUI URGENTE",
            "body": "Sua conta sera bloqueada em 24h. Aja agora!",
            "sender": "alerta@empresa.test",
            "urls_in_body": [],
        }
        response = client.post("/analyze-email", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["label"] != "PHISHING"
        # final_prob capado em 0.60 → SUSPICIOUS (>=0.4) ou LEGITIMO

    def test_corroborated_majority_phishing_triggers_phishing(self):
        """Maioria de URLs phishing + texto suspeito → gate 2 corrobora → PHISHING."""
        _set_email_model_output([-2.0, 2.0])  # email_prob ~= 0.982
        # 2 de 3 URLs phishing (ratio=0.667)
        def bert_side_effect(url):
            return 0.95 if "phish" in url else 0.05
        payload = {
            "subject": "Action required",
            "body": "Verify your identity immediately.",
            "sender": "noreply@attacker.test",
            "urls_in_body": [
                "https://phish1.test/login",
                "https://phish2.test/verify",
                "https://legitsite.test/home",
            ],
        }
        with patch("app._bert_predict", side_effect=bert_side_effect):
            response = client.post("/analyze-email", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["label"] == "PHISHING"


class TestHealthEmailModel:
    """Test /health includes email_model_loaded field."""

    def test_health_includes_email_model_loaded(self):
        """Health check reports email_model_loaded: true."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "email_model_loaded" in data
        assert data["email_model_loaded"] is True

    def test_health_version_4(self):
        """Health check reports version 4.0.0."""
        data = client.get("/health").json()
        assert data["version"] == "4.0.0"
