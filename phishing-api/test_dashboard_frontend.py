"""
Tests for US-010 — Dashboard Frontend (static file serving).

Verifies that:
- GET /dashboard-ui redirects to /dashboard-ui/
- GET /dashboard-ui/ returns the index.html (200 OK, HTML content type)
- The HTML contains expected dashboard elements
"""

import pytest
from unittest.mock import patch, MagicMock
import torch


# ---------------------------------------------------------------------------
# App bootstrapping (same pattern as other test files)
# ---------------------------------------------------------------------------

def _create_mock_model():
    mock_model = MagicMock()
    mock_model.parameters.side_effect = lambda: iter([torch.tensor([1.0])])
    mock_model.eval.return_value = None
    return mock_model


def _create_mock_tokenizer():
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
    app_module.email_model = _create_mock_model()
    app_module.email_tokenizer = _create_mock_tokenizer()
    app_module.translation_model = None
    app_module.translation_tokenizer = None


_mock_server_features = MagicMock()

with patch("app.load_model", _mock_load_model), \
     patch("server_features.extract_server_features", _mock_server_features):
    from app import app
    from fastapi.testclient import TestClient

    _mock_load_model()
    client = TestClient(app, follow_redirects=False)
    client_follow = TestClient(app, follow_redirects=True)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_dashboard_ui_redirect():
    """GET /dashboard-ui should redirect to /dashboard-ui/"""
    resp = client.get("/dashboard-ui")
    assert resp.status_code in (301, 302, 307, 308)
    assert "/dashboard-ui/" in resp.headers.get("location", "")


def test_dashboard_ui_index_html():
    """GET /dashboard-ui/ should return 200 with HTML content."""
    resp = client_follow.get("/dashboard-ui/")
    assert resp.status_code == 200
    content_type = resp.headers.get("content-type", "")
    assert "text/html" in content_type


def test_dashboard_ui_contains_key_elements():
    """The dashboard HTML should include chart.js and key UI text."""
    resp = client_follow.get("/dashboard-ui/")
    assert resp.status_code == 200
    body = resp.text
    # Chart.js CDN
    assert "chart.js" in body.lower()
    # Login form elements
    assert "X-API-Key" in body or "api-key" in body.lower() or "input-key" in body
    # Dashboard title
    assert "Anti-Phishing" in body or "anti-phishing" in body.lower()
    # Portuguese UI text
    assert "Phishing" in body


def test_dashboard_ui_index_html_direct():
    """GET /dashboard-ui/index.html should also return 200."""
    resp = client_follow.get("/dashboard-ui/index.html")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
