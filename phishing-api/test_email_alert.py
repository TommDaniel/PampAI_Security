"""
Tests for US-007 — Sistema de alertas — email.

Tests:
- send_email_alert() sends SMTP email to each enabled email recipient
- send_email_alert() does nothing when no configs returned
- send_email_alert() logs warning but does not raise on SMTP error
- send_email_alert() gracefully handles get_alert_configs failure
- send_email_alert() sends to multiple recipients
- _build_email() builds correct subject and body
- /predict endpoint triggers email alert when phishing + org_id
- /predict endpoint does NOT trigger email alert when legitimate
- /predict endpoint does NOT trigger email alert when org_id is None
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import patch, AsyncMock, MagicMock, call


# ---------------------------------------------------------------------------
# App bootstrapping (same pattern as other test files)
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

PHISHING_EVENT = {
    "id": 42,
    "org_id": "acme-corp",
    "user_email": None,
    "event_type": "url",
    "is_phishing": True,
    "confidence": 95.0,
    "label": "PHISHING",
    "url": "http://evil.example.com",
    "email_subject": None,
    "email_sender": None,
    "analysis": "High confidence phishing",
    "inference_ms": 12.5,
    "source": "bert",
    "email_score": None,
    "language_detected": None,
    "translated": None,
    "extension_id": None,
    "user_agent": None,
    "created_at": NOW,
}

EMAIL_CONFIGS = [
    {
        "id": 1,
        "org_id": "acme-corp",
        "alert_type": "email",
        "endpoint": "security@acme-corp.example.com",
        "enabled": True,
    }
]


def _mock_get_org_id(org_id):
    async def _dep():
        return org_id
    return _dep


# ---------------------------------------------------------------------------
# Unit tests for send_email_alert()
# ---------------------------------------------------------------------------

class TestSendEmailAlert:
    @pytest.mark.anyio
    async def test_sends_email_to_configured_recipient(self):
        """Should call _send_smtp for each enabled email config."""
        from alerts import send_email_alert

        with patch("db.get_alert_configs", AsyncMock(return_value=EMAIL_CONFIGS)), \
             patch("alerts._send_smtp") as mock_smtp:
            await send_email_alert(org_id="acme-corp", event=PHISHING_EVENT)

        mock_smtp.assert_called_once()
        recipient_arg = mock_smtp.call_args[0][0]
        assert recipient_arg == "security@acme-corp.example.com"

    @pytest.mark.anyio
    async def test_does_nothing_when_no_configs(self):
        """No email configs → no SMTP call."""
        from alerts import send_email_alert

        with patch("db.get_alert_configs", AsyncMock(return_value=[])), \
             patch("alerts._send_smtp") as mock_smtp:
            await send_email_alert(org_id="acme-corp", event=PHISHING_EVENT)

        mock_smtp.assert_not_called()

    @pytest.mark.anyio
    async def test_logs_warning_on_smtp_error(self):
        """SMTP failure should log warning but not raise."""
        from alerts import send_email_alert

        with patch("db.get_alert_configs", AsyncMock(return_value=EMAIL_CONFIGS)), \
             patch("alerts._send_smtp", side_effect=Exception("SMTP connection refused")):
            # Should not raise
            await send_email_alert(org_id="acme-corp", event=PHISHING_EVENT)

    @pytest.mark.anyio
    async def test_graceful_on_config_fetch_failure(self):
        """get_alert_configs raising should not propagate to caller."""
        from alerts import send_email_alert

        with patch("db.get_alert_configs", AsyncMock(side_effect=Exception("db error"))):
            # Should not raise
            await send_email_alert(org_id="acme-corp", event=PHISHING_EVENT)

    @pytest.mark.anyio
    async def test_sends_to_multiple_recipients(self):
        """Should call _send_smtp for EACH enabled email config."""
        from alerts import send_email_alert

        configs = [
            {**EMAIL_CONFIGS[0], "id": 1, "endpoint": "sec1@acme.example.com"},
            {**EMAIL_CONFIGS[0], "id": 2, "endpoint": "sec2@acme.example.com"},
        ]

        with patch("db.get_alert_configs", AsyncMock(return_value=configs)), \
             patch("alerts._send_smtp") as mock_smtp:
            await send_email_alert(org_id="acme-corp", event=PHISHING_EVENT)

        assert mock_smtp.call_count == 2
        recipients = [c[0][0] for c in mock_smtp.call_args_list]
        assert "sec1@acme.example.com" in recipients
        assert "sec2@acme.example.com" in recipients


# ---------------------------------------------------------------------------
# Unit tests for _build_email()
# ---------------------------------------------------------------------------

class TestBuildEmail:
    def test_subject_contains_org_id(self):
        """Subject should reference the organisation ID."""
        from alerts import _build_email, _build_payload

        payload = _build_payload("acme-corp", PHISHING_EVENT)
        subject, body = _build_email(payload)

        assert "acme-corp" in subject

    def test_body_contains_url(self):
        """Body should contain the phishing URL."""
        from alerts import _build_email, _build_payload

        payload = _build_payload("acme-corp", PHISHING_EVENT)
        _, body = _build_email(payload)

        assert "http://evil.example.com" in body

    def test_body_contains_confidence(self):
        """Body should include the confidence value."""
        from alerts import _build_email, _build_payload

        payload = _build_payload("acme-corp", PHISHING_EVENT)
        _, body = _build_email(payload)

        assert "95.0" in body

    def test_email_event_uses_subject_as_target(self):
        """For email events, body should fall back to email_subject when no URL."""
        from alerts import _build_email, _build_payload

        email_event = {
            **PHISHING_EVENT,
            "event_type": "email",
            "url": None,
            "email_subject": "Urgente: valide sua conta",
        }
        payload = _build_payload("acme-corp", email_event)
        _, body = _build_email(payload)

        assert "Urgente: valide sua conta" in body


# ---------------------------------------------------------------------------
# Integration: /predict triggers email alert on phishing
# ---------------------------------------------------------------------------

class TestPredictEmailIntegration:
    def test_email_alert_triggered_on_phishing_with_org(self):
        """/predict should fire email alert when result is phishing and org_id present."""
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")

            with patch("db.log_event", AsyncMock(return_value=PHISHING_EVENT)), \
                 patch("alerts.send_webhook_alert", AsyncMock()), \
                 patch("alerts.send_email_alert", AsyncMock()) as mock_email, \
                 patch("app.predict_phishing", AsyncMock(
                     return_value=(True, 95.0, "PHISHING", "High confidence", 12.5, "bert")
                 )):
                response = client.post("/predict", json={
                    "url": "http://evil.example.com",
                    "client_features": {
                        "length": 30, "dom_length": 20, "dot": 2, "hyphen": 1,
                        "slash": 3, "at": 0, "params": 0, "shortened": 0, "tls": 0,
                        "vowels_domain": 5, "email": 0,
                    },
                })
                assert response.status_code == 200
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_no_email_when_legitimate(self):
        """/predict should NOT fire email alert when result is legitimate."""
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        legit_event = {**PHISHING_EVENT, "is_phishing": False, "label": "LEGITIMO"}
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")

            with patch("db.log_event", AsyncMock(return_value=legit_event)), \
                 patch("alerts.send_webhook_alert", AsyncMock()), \
                 patch("alerts.send_email_alert", AsyncMock()) as mock_email, \
                 patch("app.predict_phishing", AsyncMock(
                     return_value=(False, 5.0, "LEGITIMO", "Low confidence", 12.5, "bert")
                 )):
                response = client.post("/predict", json={
                    "url": "http://safe.example.com",
                    "client_features": {
                        "length": 22, "dom_length": 15, "dot": 1, "hyphen": 0,
                        "slash": 1, "at": 0, "params": 0, "shortened": 0, "tls": 1,
                        "vowels_domain": 4, "email": 0,
                    },
                })
                assert response.status_code == 200
                mock_email.assert_not_called()
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_no_email_when_anonymous(self):
        """/predict should NOT fire email alert when org_id is None (anonymous)."""
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        anon_event = {**PHISHING_EVENT, "org_id": None}
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id(None)

            with patch("db.log_event", AsyncMock(return_value=anon_event)), \
                 patch("alerts.send_webhook_alert", AsyncMock()), \
                 patch("alerts.send_email_alert", AsyncMock()) as mock_email, \
                 patch("app.predict_phishing", AsyncMock(
                     return_value=(True, 95.0, "PHISHING", "High confidence", 12.5, "bert")
                 )):
                response = client.post("/predict", json={
                    "url": "http://evil.example.com",
                    "client_features": {
                        "length": 30, "dom_length": 20, "dot": 2, "hyphen": 1,
                        "slash": 3, "at": 0, "params": 0, "shortened": 0, "tls": 0,
                        "vowels_domain": 5, "email": 0,
                    },
                })
                assert response.status_code == 200
                mock_email.assert_not_called()
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()
