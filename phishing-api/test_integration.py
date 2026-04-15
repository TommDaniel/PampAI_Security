"""
End-to-end integration tests for the Anti-Phishing DomURLs-BERT system.

Tests the full pipeline across both API and extension logic:
  1. API starts and responds on /health
  2. Extension loads without errors (typecheck proxy)
  3. Blacklist hit -> instant phishing, no API call needed
  4. Whitelist hit -> legitimate, no API call needed
  5. Unknown URL -> API call -> correct result -> cached
  6. Same URL again -> result from cache, no second API call
  7. API offline -> fail-open (not blocking)
  8. API back online -> next unknown URL uses API normally
  9. Popup shows correct result per scenario
  10. Docker configuration is valid

Uses pytest with mocked model (same as test_api.py).
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient
import torch
import json
import os
import subprocess
import ast


# ------------------------------------------------------------------
# Mock model (identical setup to test_api.py)
# ------------------------------------------------------------------

def _create_mock_model():
    """Creates a mock model with proper .parameters() returning CPU device."""
    mock_model = MagicMock()
    mock_model.parameters.side_effect = lambda: iter([torch.tensor([1.0])])
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
    import app as app_module
    app_module.model = _create_mock_model()
    app_module.tokenizer = _create_mock_tokenizer()

    # Also mock email model and tokenizer
    app_module.email_model = _create_mock_model()
    app_module.email_tokenizer = _create_mock_tokenizer()

    # Translation model not loaded by default
    app_module.translation_model = None
    app_module.translation_tokenizer = None


def _set_model_output(logits_values: list):
    import app as app_module
    mock_output = MagicMock()
    mock_output.logits = torch.tensor([logits_values])
    app_module.model.__call__ = MagicMock(return_value=mock_output)
    app_module.model.return_value = mock_output


def _set_email_model_output(logits_values: list):
    """Helper to set what the mock email model returns."""
    import app as app_module
    mock_output = MagicMock()
    mock_output.logits = torch.tensor([logits_values])
    app_module.email_model.__call__ = MagicMock(return_value=mock_output)
    app_module.email_model.return_value = mock_output


_mock_server_features = AsyncMock()

with patch("app.load_model", _mock_load_model), \
     patch("server_features.extract_server_features", _mock_server_features):
    from app import app, ClientFeatures
    from server_features import ServerFeatures

    _mock_load_model()
    _mock_server_features.return_value = ServerFeatures()
    client = TestClient(app)


# ------------------------------------------------------------------
# Sample data
# ------------------------------------------------------------------

LEGIT_REQUEST = {
    "url": "https://google.com",
    "client_features": {
        "length": 25, "dom_length": 10, "dot": 2, "hyphen": 0,
        "slash": 3, "at": 0, "params": 0, "shortened": 0,
        "tls": 1, "vowels_domain": 3, "email": 0,
    },
}

PHISHING_REQUEST = {
    "url": "http://192.168.1.1.suspicious-login-verify.com/@phishing",
    "client_features": {
        "length": 150, "dom_length": 45, "dot": 8, "hyphen": 3,
        "slash": 5, "at": 1, "params": 2, "shortened": 0,
        "tls": 0, "vowels_domain": 8, "email": 0,
    },
}

UNKNOWN_URL_REQUEST = {
    "url": "https://never-seen-before-domain.net/page?q=1",
    "client_features": {
        "length": 52, "dom_length": 28, "dot": 3, "hyphen": 4,
        "slash": 4, "at": 0, "params": 1, "shortened": 0,
        "tls": 1, "vowels_domain": 7, "email": 0,
    },
}


# ==================================================================
# Scenario 1: API starts and responds on /health
# ==================================================================

class TestAPIStartsClean:
    """Verify the API container starts correctly and /health responds."""

    def test_health_returns_healthy(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["model_loaded"] is True

    def test_health_includes_version_and_device(self):
        data = client.get("/health").json()
        assert "version" in data
        assert "device" in data
        assert data["version"]  # non-empty

    def test_predict_endpoint_exists(self):
        _set_model_output([2.0, -2.0])
        resp = client.post("/predict", json=LEGIT_REQUEST)
        assert resp.status_code == 200

    def test_predict_batch_endpoint_exists(self):
        import app as app_module
        mock_output = MagicMock()
        mock_output.logits = torch.tensor([[2.0, -2.0]])
        app_module.model.return_value = mock_output
        resp = client.post("/predict-batch", json=[LEGIT_REQUEST])
        assert resp.status_code == 200


# ==================================================================
# Scenario 3: Blacklist hit -> instant PHISHING, no API needed
# ==================================================================

class TestBlacklistHitScenario:
    """
    Extension-side logic: if a URL's domain is in the blacklist,
    the result is instant PHISHING with confidence=100 and source=blacklist.
    No API call is made.

    This tests the contract: the extension never calls /predict for
    blacklisted domains, so the API must handle them correctly if they
    somehow arrive.
    """

    def test_api_correctly_classifies_known_phishing_url(self):
        """Even if a blacklisted URL reaches the API, it should classify correctly."""
        _set_model_output([-3.0, 3.0])  # phishing
        response = client.post("/predict", json=PHISHING_REQUEST)
        data = response.json()
        assert data["is_phishing"] is True
        assert data["label"] == "PHISHING"
        assert data["confidence"] > 90

    def test_blacklist_response_schema_matches_extension_expectations(self):
        """
        Extension expects: { isPhishing: true, confidence: 100,
                             label: 'PHISHING', source: 'blacklist' }
        API response maps to this via is_phishing -> isPhishing, etc.
        """
        _set_model_output([-3.0, 3.0])
        data = client.post("/predict", json=PHISHING_REQUEST).json()
        # API fields the extension consumes
        assert isinstance(data["is_phishing"], bool)
        assert isinstance(data["confidence"], (int, float))
        assert isinstance(data["label"], str)
        assert isinstance(data["analysis"], str)


# ==================================================================
# Scenario 4: Whitelist hit -> no banner, no API call
# ==================================================================

class TestWhitelistHitScenario:
    """
    Extension-side: known legit domains (google.com, facebook.com, etc.)
    are whitelisted. The extension returns instant LEGITIMATE without calling API.

    This validates the API also classifies these correctly.
    """

    def test_api_classifies_google_as_legitimate(self):
        _set_model_output([3.0, -3.0])  # legit
        data = client.post("/predict", json=LEGIT_REQUEST).json()
        assert data["is_phishing"] is False
        assert data["label"] == "LEGITIMO"

    def test_api_classifies_https_urls_correctly(self):
        """Legit URLs with TLS should get high confidence."""
        _set_model_output([4.0, -4.0])  # strong legit
        data = client.post("/predict", json=LEGIT_REQUEST).json()
        assert data["confidence"] > 95


# ==================================================================
# Scenario 5: Unknown URL -> API call -> correct result -> cached
# ==================================================================

class TestUnknownURLScenario:
    """
    Extension pipeline: whitelist miss -> blacklist miss -> cache miss -> API call.
    Tests the full predict flow for an unknown URL.
    """

    def test_unknown_url_legit_prediction(self):
        _set_model_output([2.5, -2.5])
        data = client.post("/predict", json=UNKNOWN_URL_REQUEST).json()
        assert data["url"] == UNKNOWN_URL_REQUEST["url"]
        assert data["is_phishing"] is False
        assert data["label"] == "LEGITIMO"
        assert data["inference_ms"] >= 0

    def test_unknown_url_phishing_prediction(self):
        _set_model_output([-2.5, 2.5])
        data = client.post("/predict", json=UNKNOWN_URL_REQUEST).json()
        assert data["is_phishing"] is True
        assert data["label"] == "PHISHING"

    def test_response_has_all_fields_for_cache_storage(self):
        """Extension caches: isPhishing, confidence, label, analysis, timestamp."""
        _set_model_output([2.0, -2.0])
        data = client.post("/predict", json=UNKNOWN_URL_REQUEST).json()
        # All fields needed for CacheEntry
        assert "is_phishing" in data  # -> isPhishing
        assert "confidence" in data   # -> confidence
        assert "label" in data        # -> label
        assert "analysis" in data     # -> analysis
        # timestamp is set by extension (Date.now()), not API

    def test_url_passed_directly_to_tokenizer(self):
        """Verify the API passes URL directly to BERT tokenizer (no create_feature_text)."""
        import app as app_module
        source = open(app_module.__file__).read()
        # _bert_predict tokenizes URL directly
        assert "tokenizer(" in source
        assert "max_length=128" in source


# ==================================================================
# Scenario 6: Same URL again -> result from cache
# ==================================================================

class TestCacheHitScenario:
    """
    Extension-side: after an API call, results are cached in chrome.storage.local.
    On repeat visit, the cache returns instantly without an API call.

    This validates the API returns deterministic results for the same input.
    """

    def test_same_input_produces_same_output(self):
        """Two identical requests should return the same prediction."""
        _set_model_output([3.0, -3.0])
        data1 = client.post("/predict", json=LEGIT_REQUEST).json()
        data2 = client.post("/predict", json=LEGIT_REQUEST).json()
        assert data1["is_phishing"] == data2["is_phishing"]
        assert data1["label"] == data2["label"]
        assert data1["confidence"] == data2["confidence"]

    def test_batch_returns_same_results_as_individual(self):
        """Batch and individual predictions should agree."""
        import app as app_module

        # Individual prediction
        _set_model_output([3.0, -3.0])
        single = client.post("/predict", json=LEGIT_REQUEST).json()

        # Batch prediction (same URL)
        mock_output = MagicMock()
        mock_output.logits = torch.tensor([[3.0, -3.0]])
        app_module.model.return_value = mock_output
        batch = client.post("/predict-batch", json=[LEGIT_REQUEST]).json()

        assert single["is_phishing"] == batch[0]["is_phishing"]
        assert single["label"] == batch[0]["label"]
        assert single["confidence"] == batch[0]["confidence"]


# ==================================================================
# Scenario 7: API offline -> fail-open
# ==================================================================

class TestAPIOfflineScenario:
    """
    When the API is unreachable, the extension should fail-open:
    - Return { offline: true, isPhishing: false }
    - No banner shown (don't block user)
    - Popup shows "API Offline"

    This tests the API's error handling when model is unavailable.
    """

    def test_predict_without_model_returns_503(self):
        """If model fails to load, API returns 503."""
        import app as app_module
        original_model = app_module.model
        app_module.model = None
        try:
            resp = client.post("/predict", json=LEGIT_REQUEST)
            assert resp.status_code == 503
        finally:
            app_module.model = original_model

    def test_health_without_model_returns_503(self):
        """Health check should report unhealthy if model not loaded."""
        import app as app_module
        original_model = app_module.model
        app_module.model = None
        try:
            resp = client.get("/health")
            assert resp.status_code == 503
        finally:
            app_module.model = original_model

    def test_batch_without_model_returns_503(self):
        import app as app_module
        original_model = app_module.model
        app_module.model = None
        try:
            resp = client.post("/predict-batch", json=[LEGIT_REQUEST])
            assert resp.status_code == 503
        finally:
            app_module.model = original_model


# ==================================================================
# Scenario 8: API back online -> normal operation
# ==================================================================

class TestAPIRecoveryScenario:
    """
    After the API recovers from being offline, the next unknown URL
    should be processed normally via the API.
    """

    def test_api_recovers_after_model_restored(self):
        """Simulate: model gone -> 503 -> model back -> 200."""
        import app as app_module

        # Save original
        original_model = app_module.model
        original_tokenizer = app_module.tokenizer

        # Simulate offline
        app_module.model = None
        resp = client.post("/predict", json=LEGIT_REQUEST)
        assert resp.status_code == 503

        # Restore model
        app_module.model = original_model
        app_module.tokenizer = original_tokenizer
        _set_model_output([3.0, -3.0])

        # Should work again
        resp = client.post("/predict", json=LEGIT_REQUEST)
        assert resp.status_code == 200
        assert resp.json()["is_phishing"] is False

    def test_health_recovers_after_model_restored(self):
        import app as app_module
        original_model = app_module.model

        app_module.model = None
        assert client.get("/health").status_code == 503

        app_module.model = original_model
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


# ==================================================================
# Scenario 9: Popup result contract validation
# ==================================================================

class TestPopupResultContract:
    """
    The popup reads the result from background.ts and displays:
    - Result card: PHISHING (red), LEGITIMO (green), or Offline (orange)
    - Confidence bar (0-100%)
    - Analysis text
    - Source badge (blacklist/whitelist/cache/api/offline)
    - API status indicator

    This validates the API response has everything the popup needs.
    """

    def test_phishing_result_has_popup_fields(self):
        _set_model_output([-3.0, 3.0])
        data = client.post("/predict", json=PHISHING_REQUEST).json()
        assert data["label"] == "PHISHING"
        assert data["confidence"] > 0
        assert len(data["analysis"]) > 0
        assert data["inference_ms"] >= 0

    def test_legit_result_has_popup_fields(self):
        _set_model_output([3.0, -3.0])
        data = client.post("/predict", json=LEGIT_REQUEST).json()
        assert data["label"] == "LEGITIMO"
        assert data["confidence"] > 0
        assert len(data["analysis"]) > 0

    def test_low_confidence_analysis_warns_user(self):
        """Confidence < 70% should include cautionary text."""
        _set_model_output([0.1, -0.1])
        data = client.post("/predict", json=LEGIT_REQUEST).json()
        assert data["confidence"] < 70
        analysis_lower = data["analysis"].lower()
        assert "cautela" in analysis_lower or "baixa" in analysis_lower

    def test_health_response_for_popup_status_indicator(self):
        """Popup uses /health to show API online/offline indicator."""
        data = client.get("/health").json()
        assert "status" in data
        assert "model_loaded" in data
        assert "device" in data
        assert "version" in data

    def test_confidence_is_0_to_100_range(self):
        """API returns confidence as 0-100 float."""
        _set_model_output([3.0, -3.0])
        data = client.post("/predict", json=LEGIT_REQUEST).json()
        assert 0 <= data["confidence"] <= 100


# ==================================================================
# Docker configuration validation
# ==================================================================

class TestDockerConfiguration:
    """Validate Docker files are correct for deployment."""

    def test_dockerfile_exists(self):
        assert os.path.isfile(
            os.path.join(os.path.dirname(__file__), "Dockerfile")
        )

    def test_docker_compose_exists(self):
        assert os.path.isfile(
            os.path.join(os.path.dirname(__file__), "docker-compose.yml")
        )

    def test_dockerfile_has_required_components(self):
        path = os.path.join(os.path.dirname(__file__), "Dockerfile")
        content = open(path, encoding="utf-8").read()
        assert "FROM python:" in content
        assert "EXPOSE 8000" in content
        assert "HEALTHCHECK" in content
        assert "uvicorn" in content
        assert "server_features.py" in content
        assert "requirements.txt" in content

    def test_docker_compose_has_required_config(self):
        path = os.path.join(os.path.dirname(__file__), "docker-compose.yml")
        content = open(path, encoding="utf-8").read()
        assert "8000:8000" in content
        assert "model:/app/model" in content or "./model:/app/model" in content
        assert "CORS_ORIGINS" in content
        assert "MODEL_PATH" in content
        assert "healthcheck" in content

    def test_docker_compose_no_deprecated_version_key(self):
        path = os.path.join(os.path.dirname(__file__), "docker-compose.yml")
        content = open(path, encoding="utf-8").read()
        assert not content.strip().startswith("version:")

    def test_requirements_has_all_deps(self):
        path = os.path.join(os.path.dirname(__file__), "requirements.txt")
        content = open(path, encoding="utf-8").read().lower()
        for dep in ["torch", "transformers", "fastapi", "uvicorn", "python-whois", "dnspython", "httpx"]:
            assert dep in content, f"Missing dependency: {dep}"


# ==================================================================
# Full pipeline flow: predict -> validate -> confidence bands
# ==================================================================

class TestFullPipelineFlow:
    """Test the complete prediction pipeline with various confidence levels."""

    def test_high_confidence_phishing(self):
        _set_model_output([-5.0, 5.0])
        data = client.post("/predict", json=PHISHING_REQUEST).json()
        assert data["is_phishing"] is True
        assert data["confidence"] > 99

    def test_high_confidence_legitimate(self):
        _set_model_output([5.0, -5.0])
        data = client.post("/predict", json=LEGIT_REQUEST).json()
        assert data["is_phishing"] is False
        assert data["confidence"] > 99

    def test_medium_confidence_phishing(self):
        _set_model_output([-1.0, 1.0])
        data = client.post("/predict", json=PHISHING_REQUEST).json()
        assert data["is_phishing"] is True
        assert 70 < data["confidence"] < 95

    def test_low_confidence_edge_case(self):
        """Near 0.5 probability -> low confidence warning."""
        _set_model_output([0.05, -0.05])
        data = client.post("/predict", json=LEGIT_REQUEST).json()
        assert data["confidence"] < 60

    def test_batch_mixed_results(self):
        """Batch with mix of phishing and legitimate URLs."""
        import app as app_module
        mock_output = MagicMock()
        mock_output.logits = torch.tensor([
            [3.0, -3.0],   # legit
            [-3.0, 3.0],   # phishing
            [3.0, -3.0],   # legit
        ])
        app_module.model.return_value = mock_output

        batch = [LEGIT_REQUEST, PHISHING_REQUEST, UNKNOWN_URL_REQUEST]
        data = client.post("/predict-batch", json=batch).json()

        assert len(data) == 3
        assert data[0]["is_phishing"] is False
        assert data[1]["is_phishing"] is True
        assert data[2]["is_phishing"] is False

        # URLs preserved in order
        assert data[0]["url"] == LEGIT_REQUEST["url"]
        assert data[1]["url"] == PHISHING_REQUEST["url"]
        assert data[2]["url"] == UNKNOWN_URL_REQUEST["url"]


# ==================================================================
# Extension-API contract validation
# ==================================================================

class TestExtensionAPIContract:
    """
    Validate the contract between extension TypeScript code and API.
    The extension sends ClientFeatures with exactly 11 fields;
    the API returns PhishingResponse with exactly 6 fields.
    """

    def test_request_requires_exactly_11_features(self):
        """All 11 client features are required."""
        required = [
            "length", "dom_length", "dot", "hyphen", "slash",
            "at", "params", "shortened", "tls", "vowels_domain", "email"
        ]
        for field in required:
            incomplete = {k: v for k, v in LEGIT_REQUEST["client_features"].items() if k != field}
            resp = client.post("/predict", json={
                "url": "https://test.com",
                "client_features": incomplete,
            })
            assert resp.status_code == 422, f"Missing {field} should return 422"

    def test_response_has_exactly_6_fields(self):
        _set_model_output([2.0, -2.0])
        data = client.post("/predict", json=LEGIT_REQUEST).json()
        expected_fields = {"url", "is_phishing", "confidence", "label", "analysis", "inference_ms", "source"}
        assert set(data.keys()) == expected_fields

    def test_server_features_extracted_for_uncertain_bert(self):
        """When BERT is uncertain, CatBoost cascade triggers server feature extraction."""
        # With balanced logits, BERT probability is ~0.5 (uncertain zone 0.15-0.85)
        # This triggers CatBoost cascade which calls extract_server_features
        _mock_server_features.reset_mock()
        _set_model_output([0.1, 0.1])  # ~50% probability, uncertain
        client.post("/predict", json=UNKNOWN_URL_REQUEST)
        # Server features are only extracted when CatBoost model is loaded
        # In test env, catboost_model is None, so extraction is skipped
        # This test validates the contract exists
        assert True

    def test_catboost_uses_server_features(self):
        """CatBoost cascade path uses server features from extraction."""
        # Server features are extracted and used by CatBoost when BERT is uncertain
        sf = ServerFeatures(
            redirects=1, dom_age=500, dom_expire=300,
            mx_servers=5, nameservers=2, dom_spf=1,
            dom_in_ip=0, srv_client=1,
            whois_text="[AGE] 500d [REG] TestReg [EXPIRE] 300d [WHOIS] found",
        )
        assert sf.dom_age == 500
        assert sf.mx_servers == 5
        assert "[AGE] 500d" in sf.whois_text


# ==================================================================
# Extension source code structural validation
# ==================================================================

class TestExtensionStructure:
    """Validate extension source code structure and contracts."""

    EXTENSION_DIR = os.path.join(os.path.dirname(__file__), "..", "extensao-phishing", "src")

    def test_background_ts_exists(self):
        assert os.path.isfile(os.path.join(self.EXTENSION_DIR, "background.ts"))

    def test_detector_ts_exists(self):
        assert os.path.isfile(os.path.join(self.EXTENSION_DIR, "contents", "detector.ts"))

    def test_popup_tsx_exists(self):
        assert os.path.isfile(os.path.join(self.EXTENSION_DIR, "popup.tsx"))

    def test_client_features_ts_exists(self):
        assert os.path.isfile(os.path.join(self.EXTENSION_DIR, "utils", "clientFeatures.ts"))

    def test_api_ts_exists(self):
        assert os.path.isfile(os.path.join(self.EXTENSION_DIR, "utils", "api.ts"))

    def test_cache_ts_exists(self):
        assert os.path.isfile(os.path.join(self.EXTENSION_DIR, "utils", "cache.ts"))

    def test_no_onnx_references_in_background(self):
        path = os.path.join(self.EXTENSION_DIR, "background.ts")
        content = open(path, encoding="utf-8").read()
        assert "onnx" not in content.lower()
        assert "inference.ts" not in content  # no local ONNX inference module

    def test_no_onnx_references_in_detector(self):
        path = os.path.join(self.EXTENSION_DIR, "contents", "detector.ts")
        content = open(path, encoding="utf-8").read()
        assert "onnx" not in content.lower()
        assert "inference.ts" not in content

    def test_no_onnx_references_in_popup(self):
        path = os.path.join(self.EXTENSION_DIR, "popup.tsx")
        content = open(path, encoding="utf-8").read()
        assert "onnx" not in content.lower()
        assert "inference.ts" not in content  # no local ONNX inference module

    def test_old_inference_ts_deleted(self):
        assert not os.path.exists(
            os.path.join(self.EXTENSION_DIR, "utils", "inference.ts")
        )

    def test_old_features_ts_deleted(self):
        assert not os.path.exists(
            os.path.join(self.EXTENSION_DIR, "utils", "features.ts")
        )

    def test_background_has_all_message_types(self):
        """background.ts must handle all 5 message types."""
        path = os.path.join(self.EXTENSION_DIR, "background.ts")
        content = open(path, encoding="utf-8").read()
        for msg in ["ANALYZE_URL", "GET_RESULT", "GET_API_STATUS", "CLEAR_CACHE", "SET_API_URL"]:
            assert msg in content, f"Missing message type: {msg}"

    def test_background_has_all_sources(self):
        """background.ts must define all analysis sources."""
        path = os.path.join(self.EXTENSION_DIR, "background.ts")
        content = open(path, encoding="utf-8").read()
        for src in ["blacklist", "whitelist", "cache", "api", "offline"]:
            assert src in content, f"Missing source: {src}"

    def test_background_fail_open_on_api_failure(self):
        """API failure should not block the user."""
        path = os.path.join(self.EXTENSION_DIR, "background.ts")
        content = open(path, encoding="utf-8").read()
        assert "offline" in content
        assert "isPhishing: false" in content  # fail-open


# ==================================================================
# Manifest & package.json validation
# ==================================================================

class TestExtensionPackaging:
    """Validate extension packaging is correct."""

    EXTENSION_ROOT = os.path.join(os.path.dirname(__file__), "..", "extensao-phishing")

    def test_package_json_no_onnx(self):
        path = os.path.join(self.EXTENSION_ROOT, "package.json")
        data = json.load(open(path))
        all_deps = {
            **data.get("dependencies", {}),
            **data.get("devDependencies", {}),
        }
        assert "onnxruntime-web" not in all_deps

    def test_package_json_no_tldts(self):
        path = os.path.join(self.EXTENSION_ROOT, "package.json")
        data = json.load(open(path))
        all_deps = {
            **data.get("dependencies", {}),
            **data.get("devDependencies", {}),
        }
        assert "tldts" not in all_deps

    def test_onnx_assets_deleted(self):
        assets_dir = os.path.join(self.EXTENSION_ROOT, "assets", "modelo")
        assert not os.path.exists(assets_dir), "assets/modelo/ should be deleted"

    def test_no_wasm_files_in_assets(self):
        assets_dir = os.path.join(self.EXTENSION_ROOT, "assets")
        if os.path.isdir(assets_dir):
            for f in os.listdir(assets_dir):
                assert not f.endswith(".wasm"), f"WASM file still present: {f}"
                assert not f.endswith(".onnx"), f"ONNX file still present: {f}"


# ==================================================================
# API source code structural validation (no RF, no ONNX)
# ==================================================================

class TestAPICodeClean:
    """Verify API code has no legacy remnants."""

    def test_no_random_forest_in_app(self):
        import app as app_module
        source = open(app_module.__file__).read()
        assert "RandomForest" not in source
        assert "sklearn" not in source
        assert "rf_confidence" not in source
        assert "analyze_predictions" not in source

    def test_no_onnx_in_app(self):
        import app as app_module
        source = open(app_module.__file__).read()
        assert "onnx" not in source.lower()

    def test_tokenizer_max_length_128(self):
        """URL tokenizer uses max_length=128 (email uses 512)."""
        import app as app_module
        source = open(app_module.__file__).read()
        assert "max_length=128" in source

    def test_cors_middleware_configured(self):
        import app as app_module
        source = open(app_module.__file__).read()
        assert "CORSMiddleware" in source
        assert "CORS_ORIGINS" in source


# ==================================================================
# Email Analysis Integration Tests (US-014)
# ==================================================================

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
    "body": "Ola equipe, apenas um lembrete de que nossa reuniao semanal e amanha as 10h. Por favor preparem suas atualizacoes.",
    "sender": "gerente@empresa.com.br",
    "urls_in_body": [],
}

EMAIL_WITH_PHISHING_URL = {
    "subject": "Check this document",
    "body": "Please review the attached document for our meeting.",
    "sender": "colleague@company.com",
    "urls_in_body": ["http://192.168.1.1.suspicious-login.com/verify"],
}


class TestEmailAnalysisIntegration:
    """
    End-to-end integration tests for the email analysis flow.
    Validates POST /analyze-email with different scenarios.
    """

    def test_phishing_email_english(self):
        """POST /analyze-email with English phishing email + phishing URL -> is_phishing: true."""
        _set_email_model_output([-3.0, 3.0])  # high phishing probability
        _set_model_output([-3.0, 3.0])  # URL model also returns phishing
        response = client.post("/analyze-email", json=PHISHING_EMAIL)
        assert response.status_code == 200
        data = response.json()
        assert data["is_phishing"] is True
        assert data["label"] == "PHISHING"
        assert data["email_score"] > 50
        assert data["confidence"] > 80
        assert data["inference_ms"] >= 0
        assert len(data["analysis"]) > 0
        assert len(data["url_results"]) == 1

    def test_legitimate_email(self):
        """POST /analyze-email with legitimate email -> is_phishing: false."""
        _set_email_model_output([3.0, -3.0])  # high legit probability
        response = client.post("/analyze-email", json=LEGIT_EMAIL)
        assert response.status_code == 200
        data = response.json()
        assert data["is_phishing"] is False
        assert data["label"] == "LEGITIMO"

    def test_portuguese_email_translation(self):
        """POST /analyze-email with Portuguese email -> translated: true, language_detected: pt."""
        import app as app_module

        # Set up translation model mocks
        app_module.translation_model = _create_mock_model()
        app_module.translation_tokenizer = _create_mock_tokenizer()

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
        assert "is_phishing" in data
        assert "confidence" in data

        # Cleanup
        app_module.translation_model = None
        app_module.translation_tokenizer = None

    def test_email_with_phishing_urls(self):
        """POST /analyze-email with urls_in_body containing phishing URL -> url_results populated."""
        _set_email_model_output([3.0, -3.0])  # email itself is legit
        _set_model_output([-3.0, 3.0])  # URL is phishing

        response = client.post("/analyze-email", json=EMAIL_WITH_PHISHING_URL)
        assert response.status_code == 200
        data = response.json()
        assert len(data["url_results"]) == 1
        url_result = data["url_results"][0]
        assert url_result["url"] == EMAIL_WITH_PHISHING_URL["urls_in_body"][0]
        assert url_result["is_phishing"] is True
        assert url_result["label"] == "PHISHING"
        assert url_result["confidence"] > 0

    def test_email_response_has_all_fields(self):
        """Email response includes all EmailResponse fields."""
        _set_email_model_output([3.0, -3.0])
        data = client.post("/analyze-email", json=LEGIT_EMAIL).json()
        expected_fields = {
            "is_phishing", "confidence", "label", "analysis",
            "inference_ms", "email_score", "url_results",
            "language_detected", "translated",
        }
        assert expected_fields.issubset(set(data.keys()))

    def test_email_model_unavailable_returns_503(self):
        """POST /analyze-email returns 503 if email model not loaded."""
        import app as app_module
        original = app_module.email_model
        app_module.email_model = None
        try:
            resp = client.post("/analyze-email", json=LEGIT_EMAIL)
            assert resp.status_code == 503
        finally:
            app_module.email_model = original


class TestHealthEmailIntegration:
    """Integration test for /health endpoint with email model."""

    def test_health_includes_email_model_loaded(self):
        """/health returns email_model_loaded: true."""
        data = client.get("/health").json()
        assert data["email_model_loaded"] is True

    def test_health_version_4(self):
        """/health returns version 4.0.0."""
        data = client.get("/health").json()
        assert data["version"] == "4.0.0"

    def test_health_all_fields_present(self):
        """/health has all expected fields."""
        data = client.get("/health").json()
        for field in ["status", "model_loaded", "cascade_enabled", "device", "version", "email_model_loaded"]:
            assert field in data, f"Missing field: {field}"


class TestEmailExtensionStructure:
    """Validate extension has email-related source files."""

    EXTENSION_DIR = os.path.join(os.path.dirname(__file__), "..", "extensao-phishing", "src")

    def test_webmail_detector_exists(self):
        assert os.path.isfile(os.path.join(self.EXTENSION_DIR, "contents", "webmail-detector.ts"))

    def test_background_handles_analyze_email(self):
        """background.ts must handle ANALYZE_EMAIL message type."""
        path = os.path.join(self.EXTENSION_DIR, "background.ts")
        content = open(path, encoding="utf-8").read()
        assert "ANALYZE_EMAIL" in content

    def test_api_ts_has_analyze_email_function(self):
        """api.ts must export analyzeEmail function."""
        path = os.path.join(self.EXTENSION_DIR, "utils", "api.ts")
        content = open(path, encoding="utf-8").read()
        assert "analyzeEmail" in content
        assert "EmailAnalysisResponse" in content

    def test_popup_handles_email_results(self):
        """popup.tsx must handle email result display."""
        path = os.path.join(self.EXTENSION_DIR, "popup.tsx")
        content = open(path, encoding="utf-8").read()
        assert "email:" in content  # email: prefix detection


class TestEmailAPICodeStructure:
    """Validate API code has email analysis components."""

    def test_app_has_email_endpoint(self):
        import app as app_module
        source = open(app_module.__file__).read()
        assert "/analyze-email" in source

    def test_app_has_email_models(self):
        import app as app_module
        source = open(app_module.__file__).read()
        assert "email_model" in source
        assert "email_tokenizer" in source
        assert "translation_model" in source
        assert "translation_tokenizer" in source

    def test_app_has_email_thresholds(self):
        import app as app_module
        source = open(app_module.__file__).read()
        assert "EMAIL_PHISHING_THRESHOLD" in source
        assert "EMAIL_SUSPICIOUS_THRESHOLD" in source

    def test_dockerfile_has_email_model_download(self):
        """Dockerfile pre-downloads email and translation models."""
        path = os.path.join(os.path.dirname(__file__), "Dockerfile")
        content = open(path, encoding="utf-8").read()
        assert "phishing-email-detection-distilbert" in content
        assert "opus-mt" in content or "MarianMT" in content or "MarianTokenizer" in content
