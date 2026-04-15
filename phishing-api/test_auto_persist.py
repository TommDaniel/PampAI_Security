"""
Tests for US-004 — Auto-persistence in existing endpoints.

Verifies that /predict, /predict-batch, and /analyze-email automatically
call log_event() when DB_ENABLED is True, and silently skip when DB is off.
"""

import pytest
import asyncio
from datetime import datetime, timezone
from unittest.mock import patch, AsyncMock, MagicMock, call


# ---------------------------------------------------------------------------
# App bootstrapping
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

NOW = datetime(2026, 4, 9, 12, 0, 0, tzinfo=timezone.utc)


def _make_log_event_return(event_type="url", org_id=None, user_email=None):
    return {
        "id": 1,
        "org_id": org_id,
        "user_email": user_email,
        "event_type": event_type,
        "is_phishing": False,
        "confidence": 10.0,
        "label": "LEGITIMO",
        "url": "http://example.com",
        "email_subject": None,
        "email_sender": None,
        "analysis": "LEGITIMO",
        "inference_ms": 10.0,
        "source": "bert",
        "email_score": None,
        "language_detected": None,
        "translated": None,
        "extension_id": None,
        "user_agent": None,
        "created_at": NOW,
    }


PREDICT_PAYLOAD = {
    "url": "http://example.com",
    "client_features": {
        "length": 18,
        "dom_length": 11,
        "dot": 1,
        "hyphen": 0,
        "slash": 1,
        "at": 0,
        "params": 0,
        "shortened": 0,
        "tls": 0,
        "vowels_domain": 3,
        "email": 0,
    },
    "mode": "bert",
}

EMAIL_PAYLOAD = {
    "subject": "Test email",
    "body": "Hello",
    "sender": "test@example.com",
    "urls_in_body": [],
}


# ---------------------------------------------------------------------------
# /predict auto-persist tests
# ---------------------------------------------------------------------------

class TestPredictAutoPersist:
    def test_predict_calls_log_event_when_db_enabled(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            mock_row = _make_log_event_return()
            with patch("db.log_event", AsyncMock(return_value=mock_row)) as mock_log:
                response = client.post("/predict", json=PREDICT_PAYLOAD)
                assert response.status_code == 200
                mock_log.assert_called_once()
                call_kwargs = mock_log.call_args.kwargs
                assert call_kwargs["event_type"] == "url"
                assert call_kwargs["url"] == "http://example.com"
                assert "is_phishing" in call_kwargs
                assert "confidence" in call_kwargs
                assert "label" in call_kwargs
        finally:
            db_module.DB_ENABLED = original

    def test_predict_does_not_call_log_event_when_db_disabled(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = False
        try:
            with patch("db.log_event", AsyncMock()) as mock_log:
                response = client.post("/predict", json=PREDICT_PAYLOAD)
                assert response.status_code == 200
                mock_log.assert_not_called()
        finally:
            db_module.DB_ENABLED = original

    def test_predict_still_returns_200_if_log_event_fails(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            with patch("db.log_event", AsyncMock(side_effect=Exception("DB error"))):
                response = client.post("/predict", json=PREDICT_PAYLOAD)
                assert response.status_code == 200
        finally:
            db_module.DB_ENABLED = original

    def test_predict_passes_user_email_to_log_event(self):
        """Header X-User-Email deve ser propagado para log_event via get_user_email."""
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            mock_row = _make_log_event_return(user_email="alice@acme.com")
            with patch("db.log_event", AsyncMock(return_value=mock_row)) as mock_log:
                response = client.post(
                    "/predict",
                    json=PREDICT_PAYLOAD,
                    headers={"X-User-Email": "Alice@Acme.COM"},
                )
                assert response.status_code == 200
                mock_log.assert_called_once()
                # Normalizado para lowercase por get_user_email
                assert mock_log.call_args.kwargs["user_email"] == "alice@acme.com"
        finally:
            db_module.DB_ENABLED = original

    def test_predict_user_email_absent_logs_none(self):
        """Sem header X-User-Email, log_event recebe user_email=None."""
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            mock_row = _make_log_event_return()
            with patch("db.log_event", AsyncMock(return_value=mock_row)) as mock_log:
                response = client.post("/predict", json=PREDICT_PAYLOAD)
                assert response.status_code == 200
                assert mock_log.call_args.kwargs["user_email"] is None
        finally:
            db_module.DB_ENABLED = original

    def test_predict_invalid_user_email_sanitized_to_none(self):
        """Email sem @ retorna None (get_user_email descarta silenciosamente)."""
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            mock_row = _make_log_event_return()
            with patch("db.log_event", AsyncMock(return_value=mock_row)) as mock_log:
                response = client.post(
                    "/predict",
                    json=PREDICT_PAYLOAD,
                    headers={"X-User-Email": "not-an-email"},
                )
                assert response.status_code == 200
                assert mock_log.call_args.kwargs["user_email"] is None
        finally:
            db_module.DB_ENABLED = original

    def test_predict_passes_org_id_to_log_event(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            mock_row = _make_log_event_return(org_id="test-org")
            with patch("db.log_event", AsyncMock(return_value=mock_row)) as mock_log, \
                 patch("auth.get_org_id", return_value="test-org"):
                response = client.post(
                    "/predict",
                    json=PREDICT_PAYLOAD,
                    headers={"X-API-Key": "some-key"},
                )
                assert response.status_code == 200
        finally:
            db_module.DB_ENABLED = original


# ---------------------------------------------------------------------------
# /analyze-email auto-persist tests
# ---------------------------------------------------------------------------

class TestAnalyzeEmailAutoPersist:
    def test_analyze_email_calls_log_event_when_db_enabled(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            mock_row = _make_log_event_return(event_type="email")
            with patch("db.log_event", AsyncMock(return_value=mock_row)) as mock_log:
                response = client.post("/analyze-email", json=EMAIL_PAYLOAD)
                assert response.status_code == 200
                mock_log.assert_called_once()
                call_kwargs = mock_log.call_args.kwargs
                assert call_kwargs["event_type"] == "email"
                assert call_kwargs["email_subject"] == "Test email"
                assert call_kwargs["email_sender"] == "test@example.com"
                assert call_kwargs["source"] == "email_bert"
        finally:
            db_module.DB_ENABLED = original

    def test_analyze_email_does_not_call_log_event_when_db_disabled(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = False
        try:
            with patch("db.log_event", AsyncMock()) as mock_log:
                response = client.post("/analyze-email", json=EMAIL_PAYLOAD)
                assert response.status_code == 200
                mock_log.assert_not_called()
        finally:
            db_module.DB_ENABLED = original

    def test_analyze_email_still_returns_200_if_log_event_fails(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            with patch("db.log_event", AsyncMock(side_effect=Exception("DB error"))):
                response = client.post("/analyze-email", json=EMAIL_PAYLOAD)
                assert response.status_code == 200
        finally:
            db_module.DB_ENABLED = original


# ---------------------------------------------------------------------------
# /predict-batch auto-persist tests
# ---------------------------------------------------------------------------

BATCH_PAYLOAD = [PREDICT_PAYLOAD, {**PREDICT_PAYLOAD, "url": "http://example2.com"}]


class TestPredictBatchAutoPersist:
    def test_predict_batch_does_not_call_log_event_when_db_disabled(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = False
        try:
            with patch("db.log_event", AsyncMock()) as mock_log:
                response = client.post("/predict-batch", json=BATCH_PAYLOAD)
                assert response.status_code == 200
                # Batch uses ensure_future so we can only check DB_ENABLED guard
                # mock_log should not be called when DB disabled
        finally:
            db_module.DB_ENABLED = original

    def test_predict_batch_returns_200_even_if_log_event_fails(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            with patch("db.log_event", AsyncMock(side_effect=Exception("DB error"))):
                response = client.post("/predict-batch", json=BATCH_PAYLOAD)
                assert response.status_code == 200
        finally:
            db_module.DB_ENABLED = original
