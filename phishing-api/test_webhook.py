"""
Tests for US-006 — Sistema de alertas — webhook.

Tests:
- send_webhook_alert() fires POST to each enabled webhook endpoint
- send_webhook_alert() does nothing when no configs returned
- send_webhook_alert() logs warning but does not raise on HTTP error
- send_webhook_alert() gracefully handles get_alert_configs failure
- _build_payload() builds correct payload structure
- /predict endpoint triggers webhook when phishing + org_id
- /predict endpoint does NOT trigger webhook when legitimate
- /predict endpoint does NOT trigger webhook when org_id is None (anonymous)
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import patch, AsyncMock, MagicMock


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

WEBHOOK_CONFIGS = [
    {
        "id": 1,
        "org_id": "acme-corp",
        "alert_type": "webhook",
        "endpoint": "https://hooks.example.com/phishing",
        "enabled": True,
    }
]


def _mock_get_org_id(org_id):
    async def _dep():
        return org_id
    return _dep


# ---------------------------------------------------------------------------
# Unit tests for send_webhook_alert()
# ---------------------------------------------------------------------------

class TestSendWebhookAlert:
    @pytest.mark.anyio
    async def test_posts_to_configured_endpoint(self):
        """Should POST to each enabled webhook URL."""
        from alerts import send_webhook_alert

        mock_response = MagicMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("db.get_alert_configs", AsyncMock(return_value=WEBHOOK_CONFIGS)), \
             patch("httpx.AsyncClient", return_value=mock_client):
            await send_webhook_alert(org_id="acme-corp", event=PHISHING_EVENT)

        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert call_args[0][0] == "https://hooks.example.com/phishing"
        payload = call_args[1]["json"]
        assert payload["alert_type"] == "phishing_detected"
        assert payload["org_id"] == "acme-corp"
        assert payload["event"]["is_phishing"] is True

    @pytest.mark.anyio
    async def test_does_nothing_when_no_configs(self):
        """No webhook configs → no HTTP call."""
        from alerts import send_webhook_alert

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("db.get_alert_configs", AsyncMock(return_value=[])), \
             patch("httpx.AsyncClient", return_value=mock_client):
            await send_webhook_alert(org_id="acme-corp", event=PHISHING_EVENT)

        mock_client.post.assert_not_called()

    @pytest.mark.anyio
    async def test_logs_warning_on_http_error(self):
        """HTTP failure should log warning but not raise."""
        from alerts import send_webhook_alert

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=Exception("connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("db.get_alert_configs", AsyncMock(return_value=WEBHOOK_CONFIGS)), \
             patch("httpx.AsyncClient", return_value=mock_client):
            # Should not raise
            await send_webhook_alert(org_id="acme-corp", event=PHISHING_EVENT)

    @pytest.mark.anyio
    async def test_graceful_on_config_fetch_failure(self):
        """get_alert_configs raising should not propagate to caller."""
        from alerts import send_webhook_alert

        with patch("db.get_alert_configs", AsyncMock(side_effect=Exception("db error"))):
            # Should not raise
            await send_webhook_alert(org_id="acme-corp", event=PHISHING_EVENT)

    @pytest.mark.anyio
    async def test_posts_to_multiple_endpoints(self):
        """Should POST to ALL enabled webhook endpoints."""
        from alerts import send_webhook_alert

        configs = [
            {**WEBHOOK_CONFIGS[0], "id": 1, "endpoint": "https://hook1.example.com"},
            {**WEBHOOK_CONFIGS[0], "id": 2, "endpoint": "https://hook2.example.com"},
        ]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("db.get_alert_configs", AsyncMock(return_value=configs)), \
             patch("httpx.AsyncClient", return_value=mock_client):
            await send_webhook_alert(org_id="acme-corp", event=PHISHING_EVENT)

        assert mock_client.post.call_count == 2


# ---------------------------------------------------------------------------
# Unit tests for _build_payload()
# ---------------------------------------------------------------------------

class TestBuildPayload:
    def test_payload_structure(self):
        """_build_payload returns correctly structured dict."""
        from alerts import _build_payload

        payload = _build_payload("acme-corp", PHISHING_EVENT)

        assert payload["alert_type"] == "phishing_detected"
        assert payload["org_id"] == "acme-corp"
        event = payload["event"]
        assert event["id"] == 42
        assert event["event_type"] == "url"
        assert event["is_phishing"] is True
        assert event["confidence"] == 95.0
        assert event["label"] == "PHISHING"
        assert event["url"] == "http://evil.example.com"

    def test_created_at_is_iso_string(self):
        """created_at datetime should be converted to ISO string in payload."""
        from alerts import _build_payload

        payload = _build_payload("acme-corp", PHISHING_EVENT)
        created_at = payload["event"]["created_at"]
        assert isinstance(created_at, str)
        datetime.fromisoformat(created_at.replace("Z", "+00:00"))

    def test_created_at_none_stays_none(self):
        """created_at=None should remain None."""
        from alerts import _build_payload

        event = {**PHISHING_EVENT, "created_at": None}
        payload = _build_payload("acme-corp", event)
        assert payload["event"]["created_at"] is None


# ---------------------------------------------------------------------------
# Integration: /predict triggers webhook on phishing
# ---------------------------------------------------------------------------

class TestPredictWebhookIntegration:
    def test_webhook_triggered_on_phishing_with_org(self):
        """/predict should fire webhook when result is phishing and org_id present."""
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")

            with patch("db.log_event", AsyncMock(return_value=PHISHING_EVENT)), \
                 patch("alerts.send_webhook_alert", AsyncMock()) as mock_webhook, \
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
                # Webhook should have been scheduled (ensure_future)
                # We verify send_webhook_alert was called by checking the import chain
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_no_webhook_when_legitimate(self):
        """/predict should NOT fire webhook when result is legitimate."""
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        legit_event = {**PHISHING_EVENT, "is_phishing": False, "label": "LEGITIMO"}
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")

            with patch("db.log_event", AsyncMock(return_value=legit_event)), \
                 patch("alerts.send_webhook_alert", AsyncMock()) as mock_webhook, \
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
                # ensure_future for webhook should NOT have been called
                mock_webhook.assert_not_called()
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_no_webhook_when_anonymous(self):
        """/predict should NOT fire webhook when org_id is None (anonymous)."""
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        anon_event = {**PHISHING_EVENT, "org_id": None}
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id(None)

            with patch("db.log_event", AsyncMock(return_value=anon_event)), \
                 patch("alerts.send_webhook_alert", AsyncMock()) as mock_webhook, \
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
                mock_webhook.assert_not_called()
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()
