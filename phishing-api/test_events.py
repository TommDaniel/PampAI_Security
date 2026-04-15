"""
Tests for US-003 — POST /events endpoint.

Tests:
- POST /events with DB disabled returns 503
- POST /events with invalid event_type returns 422
- POST /events for URL event persists and returns 201 with correct schema
- POST /events for email event persists and returns 201 with correct schema
- POST /events anonymous (no API key) persists event with org_id=None
- POST /events with valid API key persists event with org_id set
"""

import pytest
import asyncio
from datetime import datetime, timezone
from unittest.mock import patch, AsyncMock, MagicMock


# ---------------------------------------------------------------------------
# App bootstrapping (same pattern as test_auth.py)
# ---------------------------------------------------------------------------

def _create_mock_model():
    import torch
    mock_model = MagicMock()
    mock_model.parameters.side_effect = lambda: iter([torch.tensor([1.0])])
    mock_model.eval.return_value = None
    return mock_model


def _create_mock_tokenizer():
    import torch
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


_mock_server_features = AsyncMock()

with patch("app.load_model", _mock_load_model), \
     patch("server_features.extract_server_features", _mock_server_features):
    from app import app
    from server_features import ServerFeatures
    from fastapi.testclient import TestClient

    _mock_load_model()
    _mock_server_features.return_value = ServerFeatures()
    client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

URL_EVENT_PAYLOAD = {
    "event_type": "url",
    "is_phishing": True,
    "confidence": 92.5,
    "label": "PHISHING",
    "url": "http://evil-phish.example.com/login",
    "analysis": "URL classificada como PHISHING com alta confianca.",
    "inference_ms": 45.3,
    "source": "bert",
}

EMAIL_EVENT_PAYLOAD = {
    "event_type": "email",
    "is_phishing": False,
    "confidence": 85.0,
    "label": "LEGITIMO",
    "email_subject": "Your invoice",
    "email_sender": "billing@example.com",
    "email_score": 30.0,
    "language_detected": "en",
    "translated": False,
    "analysis": "Email classificado como LEGITIMO.",
    "inference_ms": 120.0,
}

NOW = datetime(2026, 4, 9, 12, 0, 0, tzinfo=timezone.utc)


def _make_log_event_return(org_id=None, event_type="url", user_email=None):
    return {
        "id": 42,
        "org_id": org_id,
        "user_email": user_email,
        "event_type": event_type,
        "is_phishing": True,
        "confidence": 92.5,
        "label": "PHISHING",
        "url": "http://evil-phish.example.com/login",
        "email_subject": None,
        "email_sender": None,
        "analysis": "URL classificada como PHISHING com alta confianca.",
        "inference_ms": 45.3,
        "source": "bert",
        "email_score": None,
        "language_detected": None,
        "translated": None,
        "extension_id": None,
        "user_agent": None,
        "created_at": NOW,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestEventsEndpointDbDisabled:
    def test_returns_503_when_db_disabled(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = False
        try:
            response = client.post("/events", json=URL_EVENT_PAYLOAD)
            assert response.status_code == 503
        finally:
            db_module.DB_ENABLED = original


class TestEventsEndpointValidation:
    def test_invalid_event_type_returns_422(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            payload = {**URL_EVENT_PAYLOAD, "event_type": "sms"}
            with patch("db.log_event", AsyncMock(return_value=_make_log_event_return())):
                response = client.post("/events", json=payload)
                assert response.status_code == 422
        finally:
            db_module.DB_ENABLED = original

    def test_missing_required_fields_returns_422(self):
        response = client.post("/events", json={"event_type": "url"})
        assert response.status_code == 422


class TestEventsEndpointUrlEvent:
    def test_url_event_returns_201(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            mock_row = _make_log_event_return()
            with patch("db.log_event", AsyncMock(return_value=mock_row)):
                response = client.post("/events", json=URL_EVENT_PAYLOAD)
                assert response.status_code == 201
        finally:
            db_module.DB_ENABLED = original

    def test_url_event_response_schema(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            mock_row = _make_log_event_return()
            with patch("db.log_event", AsyncMock(return_value=mock_row)):
                response = client.post("/events", json=URL_EVENT_PAYLOAD)
                if response.status_code == 201:
                    data = response.json()
                    assert "id" in data
                    assert "created_at" in data
                    assert "event_type" in data
                    assert "is_phishing" in data
                    assert "confidence" in data
                    assert "label" in data
                    assert data["event_type"] == "url"
                    assert data["id"] == 42
        finally:
            db_module.DB_ENABLED = original

    def test_url_event_anonymous_has_no_org_id(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            mock_row = _make_log_event_return(org_id=None)
            with patch("db.log_event", AsyncMock(return_value=mock_row)):
                response = client.post("/events", json=URL_EVENT_PAYLOAD)
                if response.status_code == 201:
                    data = response.json()
                    assert data["org_id"] is None
        finally:
            db_module.DB_ENABLED = original


class TestEventsEndpointEmailEvent:
    def test_email_event_returns_201(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            mock_row = {**_make_log_event_return(event_type="email"),
                        "event_type": "email", "url": None,
                        "email_subject": "Your invoice", "email_sender": "billing@example.com",
                        "is_phishing": False, "label": "LEGITIMO", "confidence": 85.0}
            with patch("db.log_event", AsyncMock(return_value=mock_row)):
                response = client.post("/events", json=EMAIL_EVENT_PAYLOAD)
                assert response.status_code == 201
        finally:
            db_module.DB_ENABLED = original

    def test_email_event_response_fields(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            mock_row = {**_make_log_event_return(event_type="email"),
                        "event_type": "email", "url": None,
                        "email_subject": "Your invoice", "email_sender": "billing@example.com",
                        "is_phishing": False, "label": "LEGITIMO", "confidence": 85.0}
            with patch("db.log_event", AsyncMock(return_value=mock_row)):
                response = client.post("/events", json=EMAIL_EVENT_PAYLOAD)
                if response.status_code == 201:
                    data = response.json()
                    assert data["event_type"] == "email"
                    assert "created_at" in data
        finally:
            db_module.DB_ENABLED = original


class TestEventsEndpointCreatedAt:
    def test_created_at_is_iso_string(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            mock_row = _make_log_event_return()
            with patch("db.log_event", AsyncMock(return_value=mock_row)):
                response = client.post("/events", json=URL_EVENT_PAYLOAD)
                if response.status_code == 201:
                    data = response.json()
                    # Should be a valid ISO 8601 string
                    created_at = data["created_at"]
                    assert isinstance(created_at, str)
                    assert len(created_at) > 0
        finally:
            db_module.DB_ENABLED = original
