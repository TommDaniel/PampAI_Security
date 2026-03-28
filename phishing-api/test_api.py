"""
Tests for Phishing Detection API - DomURLs-BERT
Uses pytest with FastAPI TestClient (no live server needed).
"""

import pytest
from unittest.mock import patch, MagicMock
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


# Patch load_model before creating TestClient
with patch("app.load_model", _mock_load_model):
    from app import app

    _mock_load_model()
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
        # Model returns logits for "legitimate" (class 0 high, class 1 low)
        _set_model_output([2.0, -2.0])
        response = client.post("/predict", json=SAMPLE_REQUEST)
        assert response.status_code == 200

    def test_predict_response_schema(self):
        _set_model_output([2.0, -2.0])
        response = client.post("/predict", json=SAMPLE_REQUEST)
        data = response.json()

        # All required fields present
        assert "url" in data
        assert "is_phishing" in data
        assert "confidence" in data
        assert "label" in data
        assert "analysis" in data
        assert "inference_ms" in data

        # No RF fields
        assert "rf_confidence" not in data
        assert "model_used" not in data
        assert "transformer_confidence" not in data
        assert "transformer_prediction" not in data
        assert "final_confidence" not in data

    def test_predict_legitimate(self):
        # Logits: class 0 (legit) = 3.0, class 1 (phishing) = -3.0
        _set_model_output([3.0, -3.0])
        response = client.post("/predict", json=SAMPLE_REQUEST)
        data = response.json()

        assert data["url"] == SAMPLE_REQUEST["url"]
        assert data["is_phishing"] is False
        assert data["label"] == "LEGITIMO"
        assert data["confidence"] > 0.9
        assert data["inference_ms"] >= 0

    def test_predict_phishing(self):
        # Logits: class 0 (legit) = -3.0, class 1 (phishing) = 3.0
        _set_model_output([-3.0, 3.0])
        response = client.post("/predict", json=PHISHING_REQUEST)
        data = response.json()

        assert data["url"] == PHISHING_REQUEST["url"]
        assert data["is_phishing"] is True
        assert data["label"] == "PHISHING"
        assert data["confidence"] > 0.9
        assert data["inference_ms"] >= 0

    def test_predict_low_confidence(self):
        # Logits close together = low confidence
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
            "client_features": {"length": 25},  # Missing other required fields
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
        # CORS preflight should not return 405
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
