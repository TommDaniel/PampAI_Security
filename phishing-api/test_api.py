"""
Tests for Phishing Detection API - DomURLs-BERT
Uses pytest with FastAPI TestClient (mocked model).
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient
import torch


# Mock model before importing app
def _mock_load_model():
    """Patches load_model to avoid loading the real 422MB model in tests."""
    import app as app_module

    # Create a mock model that returns predictable logits
    mock_model = MagicMock()
    mock_model.parameters.return_value = iter([torch.tensor([1.0])])  # CPU device
    mock_model.eval.return_value = None

    # Mock tokenizer
    mock_tokenizer = MagicMock()
    mock_tokenizer.return_value = {
        "input_ids": torch.tensor([[101, 102]]),
        "attention_mask": torch.tensor([[1, 1]]),
    }

    app_module.model = mock_model
    app_module.tokenizer = mock_tokenizer


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
     patch("app.extract_server_features", _mock_server_features):
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
        assert data["confidence"] > 0.9
        assert data["inference_ms"] >= 0

    def test_predict_phishing(self):
        _set_model_output([-3.0, 3.0])
        response = client.post("/predict", json=PHISHING_REQUEST)
        data = response.json()

        assert data["url"] == PHISHING_REQUEST["url"]
        assert data["is_phishing"] is True
        assert data["label"] == "PHISHING"
        assert data["confidence"] > 0.9
        assert data["inference_ms"] >= 0

    def test_predict_low_confidence(self):
        _set_model_output([0.1, -0.1])
        response = client.post("/predict", json=SAMPLE_REQUEST)
        data = response.json()

        assert data["confidence"] < 0.7
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


class TestFeatureTextFormat:
    """Validate create_feature_text matches training format."""

    def test_format_starts_with_url_token(self):
        from app import create_feature_text, ClientFeatures
        features = ClientFeatures(**SAMPLE_REQUEST["client_features"])
        text = create_feature_text("https://google.com", features)
        assert text.startswith("[URL] https://google.com")

    def test_format_contains_whois_token(self):
        from app import create_feature_text, ClientFeatures
        features = ClientFeatures(**SAMPLE_REQUEST["client_features"])
        text = create_feature_text("https://google.com", features)
        assert "[WHOIS] unknown" in text

    def test_format_contains_extra_token(self):
        from app import create_feature_text, ClientFeatures
        features = ClientFeatures(**SAMPLE_REQUEST["client_features"])
        text = create_feature_text("https://google.com", features)
        assert "[EXTRA]" in text

    def test_format_uses_key_equals_value(self):
        """Training format uses 'key=value' not 'key: value'."""
        from app import create_feature_text, ClientFeatures
        features = ClientFeatures(**SAMPLE_REQUEST["client_features"])
        text = create_feature_text("https://google.com", features)
        assert "length=25" in text
        assert "tls=1" in text
        assert "dot=2" in text
        assert "length: " not in text
        assert " | " not in text

    def test_format_no_domain_google_index(self):
        """domain_google_index is always -1, so should be omitted."""
        from app import create_feature_text, ClientFeatures
        features = ClientFeatures(**SAMPLE_REQUEST["client_features"])
        text = create_feature_text("https://google.com", features)
        assert "google_index" not in text

    def test_format_without_server_features(self):
        """Without server features, only client features appear (server defaults are -1, omitted)."""
        from app import create_feature_text, ClientFeatures
        features = ClientFeatures(**SAMPLE_REQUEST["client_features"])
        text = create_feature_text("https://google.com", features)
        expected = (
            "[URL] https://google.com [WHOIS] unknown "
            "[EXTRA] length=25 dom_length=10 dot=2 hyphen=0 slash=3 "
            "at=0 params=0 shortened=0 tls=1 vowels_domain=3 email=0"
        )
        assert text == expected

    def test_format_with_server_features(self):
        """With server features, they are interleaved in training order."""
        from app import create_feature_text, ClientFeatures
        features = ClientFeatures(**SAMPLE_REQUEST["client_features"])
        sf = ServerFeatures(
            redirects=2,
            dom_age=365,
            dom_expire=250,
            mx_servers=3,
            nameservers=4,
            dom_spf=1,
            dom_in_ip=0,
            srv_client=1,
            domain_google_index=-1,
            whois_text="[AGE] 365d [REG] GoDaddy [EXPIRE] 250d [WHOIS] found",
        )
        text = create_feature_text("https://google.com", features, server_features=sf)
        # Should use server's whois_text
        assert "[AGE] 365d [REG] GoDaddy [EXPIRE] 250d [WHOIS] found" in text
        # Should follow training order: redirects first, then client, then server interleaved
        expected = (
            "[URL] https://google.com "
            "[AGE] 365d [REG] GoDaddy [EXPIRE] 250d [WHOIS] found "
            "[EXTRA] redirects=2 length=25 dom_length=10 dot=2 hyphen=0 slash=3 "
            "at=0 params=0 shortened=0 tls=1 dom_age=365 dom_expire=250 "
            "mx_servers=3 nameservers=4 dom_spf=1 dom_in_ip=0 "
            "vowels_domain=3 srv_client=1 email=0"
        )
        assert text == expected

    def test_format_with_whois_found(self):
        """When WHOIS data is available, format includes AGE/REG/EXPIRE."""
        from app import create_feature_text, ClientFeatures
        features = ClientFeatures(**SAMPLE_REQUEST["client_features"])
        whois_text = "[AGE] 365d [REG] GoDaddy [EXPIRE] 250d [WHOIS] found"
        text = create_feature_text("https://google.com", features, whois_text=whois_text)
        assert text.startswith("[URL] https://google.com [AGE] 365d [REG] GoDaddy [EXPIRE] 250d [WHOIS] found")
        assert "[EXTRA] length=25" in text

    def test_format_partial_server_features(self):
        """When some server features fail (-1), they are omitted."""
        from app import create_feature_text, ClientFeatures
        features = ClientFeatures(**SAMPLE_REQUEST["client_features"])
        sf = ServerFeatures(
            redirects=0,
            dom_age=-1,  # WHOIS age failed
            dom_expire=-1,  # WHOIS expire failed
            mx_servers=2,
            nameservers=-1,  # NS lookup failed
            dom_spf=1,
            dom_in_ip=0,
            srv_client=-1,
            domain_google_index=-1,
            whois_text="[WHOIS] unknown",
        )
        text = create_feature_text("https://google.com", features, server_features=sf)
        assert "redirects=0" in text
        assert "mx_servers=2" in text
        assert "dom_spf=1" in text
        assert "dom_in_ip=0" in text
        assert "dom_age" not in text  # omitted (-1)
        assert "dom_expire" not in text  # omitted (-1)
        assert "nameservers" not in text  # omitted (-1)
        assert "srv_client" not in text  # omitted (-1)

    def test_tokenizer_max_length_is_128(self):
        """Tokenizer max_length must be 128 to match training."""
        import app as app_module
        source = open(app_module.__file__).read()
        assert "max_length=128" in source
        assert "max_length=512" not in source


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
        assert "[REG] A Very Long Registrar Name" in text
        # Registrar is truncated to 25 chars
        reg_part = text.split("[REG] ")[1].split(" [EXPIRE]")[0]
        assert len(reg_part) <= 25

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
                result = asyncio.get_event_loop().run_until_complete(
                    _lookup_whois_cached(found_domain)
                )
                assert result.get("status") == "found"

    def test_whois_cache_miss(self):
        """Test that WHOIS cache returns empty for unknown domains."""
        import asyncio
        from server_features import _lookup_whois_cached

        result = asyncio.get_event_loop().run_until_complete(
            _lookup_whois_cached("definitely-not-in-cache-xyz123.com")
        )
        assert result == {}

    def test_extract_server_features_returns_dataclass(self):
        """Test that extract_server_features returns ServerFeatures."""
        import asyncio
        from server_features import extract_server_features

        # Will use cache (no network), DNS/redirects will fail gracefully
        result = asyncio.get_event_loop().run_until_complete(
            extract_server_features("https://example.com")
        )
        assert isinstance(result, ServerFeatures)
        assert result.domain_google_index == -1  # always -1

    def test_extract_server_features_empty_url(self):
        """Empty URL returns all defaults."""
        import asyncio
        from server_features import extract_server_features

        result = asyncio.get_event_loop().run_until_complete(
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
            result = asyncio.get_event_loop().run_until_complete(
                extract_server_features(f"https://{found_domain}")
            )
            # WHOIS from cache should work even if DNS/redirects fail
            assert "found" in result.whois_text
            assert result.dom_age != -1 or result.dom_expire != -1
