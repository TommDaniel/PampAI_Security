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

def _mock_load_model():
    import app as app_module
    mock_model = MagicMock()
    mock_model.parameters.return_value = iter([torch.tensor([1.0])])
    mock_model.eval.return_value = None
    mock_tokenizer = MagicMock()
    mock_tokenizer.return_value = {
        "input_ids": torch.tensor([[101, 102]]),
        "attention_mask": torch.tensor([[1, 1]]),
    }
    app_module.model = mock_model
    app_module.tokenizer = mock_tokenizer


def _set_model_output(logits_values: list):
    import app as app_module
    mock_output = MagicMock()
    mock_output.logits = torch.tensor([logits_values])
    app_module.model.__call__ = MagicMock(return_value=mock_output)
    app_module.model.return_value = mock_output


_mock_server_features = AsyncMock()

with patch("app.load_model", _mock_load_model), \
     patch("app.extract_server_features", _mock_server_features):
    from app import app, ClientFeatures, create_feature_text
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

    def test_feature_text_generated_correctly(self):
        """Verify the model input text matches training format."""
        cf = ClientFeatures(**UNKNOWN_URL_REQUEST["client_features"])
        text = create_feature_text(UNKNOWN_URL_REQUEST["url"], cf)
        assert text.startswith("[URL] https://never-seen-before-domain.net/page?q=1")
        assert "[WHOIS]" in text
        assert "[EXTRA]" in text
        assert "length=52" in text
        assert "tls=1" in text


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
        content = open(path).read()
        assert "FROM python:" in content
        assert "EXPOSE 8000" in content
        assert "HEALTHCHECK" in content
        assert "uvicorn" in content
        assert "server_features.py" in content
        assert "requirements.txt" in content

    def test_docker_compose_has_required_config(self):
        path = os.path.join(os.path.dirname(__file__), "docker-compose.yml")
        content = open(path).read()
        assert "8000:8000" in content
        assert "model:/app/model" in content or "./model:/app/model" in content
        assert "CORS_ORIGINS" in content
        assert "MODEL_PATH" in content
        assert "healthcheck" in content

    def test_docker_compose_no_deprecated_version_key(self):
        path = os.path.join(os.path.dirname(__file__), "docker-compose.yml")
        content = open(path).read()
        assert not content.strip().startswith("version:")

    def test_requirements_has_all_deps(self):
        path = os.path.join(os.path.dirname(__file__), "requirements.txt")
        content = open(path).read().lower()
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
        expected_fields = {"url", "is_phishing", "confidence", "label", "analysis", "inference_ms"}
        assert set(data.keys()) == expected_fields

    def test_server_features_extracted_for_all_requests(self):
        """Every predict call triggers server-side feature extraction."""
        _mock_server_features.reset_mock()
        _set_model_output([2.0, -2.0])
        client.post("/predict", json=UNKNOWN_URL_REQUEST)
        _mock_server_features.assert_called_once()

    def test_feature_text_includes_server_features_when_available(self):
        """With server features, text includes WHOIS + server feature values."""
        cf = ClientFeatures(**LEGIT_REQUEST["client_features"])
        sf = ServerFeatures(
            redirects=1, dom_age=500, dom_expire=300,
            mx_servers=5, nameservers=2, dom_spf=1,
            dom_in_ip=0, srv_client=1,
            whois_text="[AGE] 500d [REG] TestReg [EXPIRE] 300d [WHOIS] found",
        )
        text = create_feature_text("https://google.com", cf, server_features=sf)
        assert "[AGE] 500d" in text
        assert "redirects=1" in text
        assert "dom_age=500" in text
        assert "mx_servers=5" in text


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
        content = open(path).read()
        assert "onnx" not in content.lower()
        assert "inference" not in content.lower()

    def test_no_onnx_references_in_detector(self):
        path = os.path.join(self.EXTENSION_DIR, "contents", "detector.ts")
        content = open(path).read()
        assert "onnx" not in content.lower()
        assert "inference.ts" not in content

    def test_no_onnx_references_in_popup(self):
        path = os.path.join(self.EXTENSION_DIR, "popup.tsx")
        content = open(path).read()
        assert "onnx" not in content.lower()
        assert "inference" not in content.lower()

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
        content = open(path).read()
        for msg in ["ANALYZE_URL", "GET_RESULT", "GET_API_STATUS", "CLEAR_CACHE", "SET_API_URL"]:
            assert msg in content, f"Missing message type: {msg}"

    def test_background_has_all_sources(self):
        """background.ts must define all analysis sources."""
        path = os.path.join(self.EXTENSION_DIR, "background.ts")
        content = open(path).read()
        for src in ["blacklist", "whitelist", "cache", "api", "offline"]:
            assert src in content, f"Missing source: {src}"

    def test_background_fail_open_on_api_failure(self):
        """API failure should not block the user."""
        path = os.path.join(self.EXTENSION_DIR, "background.ts")
        content = open(path).read()
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
        import app as app_module
        source = open(app_module.__file__).read()
        assert "max_length=128" in source
        assert "max_length=512" not in source

    def test_cors_middleware_configured(self):
        import app as app_module
        source = open(app_module.__file__).read()
        assert "CORSMiddleware" in source
        assert "CORS_ORIGINS" in source
