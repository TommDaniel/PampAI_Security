"""
Tests for US-008 — Alert configuration endpoints.

Endpoints tested:
- GET  /alerts/{org_id}/configs       → list alert configs
- POST /alerts/{org_id}/configs       → create alert config
- PUT  /alerts/{org_id}/configs/{id}  → update alert config
- DELETE /alerts/{org_id}/configs/{id} → delete alert config

Tests:
- Returns 503 when DB is disabled
- Returns 401 when no API key is provided
- Returns 403 when authenticated org_id doesn't match path org_id
- GET: returns list of configs (may be empty)
- POST: creates config and returns 201 with correct schema
- POST: returns 422 for invalid alert_type
- PUT: updates config and returns updated row
- PUT: returns 404 if config not found
- DELETE: deletes config and returns 204
- DELETE: returns 404 if config not found
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import patch, AsyncMock, MagicMock

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

SAMPLE_CONFIG = {
    "id": 1,
    "org_id": "acme-corp",
    "alert_type": "webhook",
    "endpoint": "https://hooks.example.com/phishing",
    "enabled": True,
    "created_at": NOW,
    "updated_at": NOW,
}

SAMPLE_EMAIL_CONFIG = {
    "id": 2,
    "org_id": "acme-corp",
    "alert_type": "email",
    "endpoint": "security@example.com",
    "enabled": True,
    "created_at": NOW,
    "updated_at": NOW,
}


def _mock_org(org_id: str):
    """Returns an async function that acts as the get_org_id dependency override."""
    async def _dep():
        return org_id
    return _dep


def _enable_db(db_module):
    original = db_module.DB_ENABLED
    db_module.DB_ENABLED = True
    return original


# ---------------------------------------------------------------------------
# GET /alerts/{org_id}/configs
# ---------------------------------------------------------------------------

class TestListAlertConfigs:
    def test_503_when_db_disabled(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = False
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("acme-corp")
            resp = client.get("/alerts/acme-corp/configs")
            assert resp.status_code == 503
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_401_without_auth(self):
        import db as db_module
        original = _enable_db(db_module)
        try:
            resp = client.get("/alerts/acme-corp/configs")
            assert resp.status_code == 401
        finally:
            db_module.DB_ENABLED = original

    def test_403_on_org_mismatch(self):
        import db as db_module
        original = _enable_db(db_module)
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("other-org")
            resp = client.get("/alerts/acme-corp/configs")
            assert resp.status_code == 403
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_200_returns_list(self):
        import db as db_module
        original = _enable_db(db_module)
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("acme-corp")
            with patch("db.list_alert_configs", AsyncMock(return_value=[SAMPLE_CONFIG, SAMPLE_EMAIL_CONFIG])):
                resp = client.get("/alerts/acme-corp/configs")
                assert resp.status_code == 200
                data = resp.json()
                assert len(data) == 2
                assert data[0]["id"] == 1
                assert data[0]["alert_type"] == "webhook"
                assert data[1]["id"] == 2
                assert data[1]["alert_type"] == "email"
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_200_returns_empty_list(self):
        import db as db_module
        original = _enable_db(db_module)
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("acme-corp")
            with patch("db.list_alert_configs", AsyncMock(return_value=[])):
                resp = client.get("/alerts/acme-corp/configs")
                assert resp.status_code == 200
                assert resp.json() == []
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_response_has_iso_timestamps(self):
        import db as db_module
        original = _enable_db(db_module)
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("acme-corp")
            with patch("db.list_alert_configs", AsyncMock(return_value=[SAMPLE_CONFIG])):
                resp = client.get("/alerts/acme-corp/configs")
                assert resp.status_code == 200
                data = resp.json()[0]
                assert isinstance(data["created_at"], str)
                assert isinstance(data["updated_at"], str)
                datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /alerts/{org_id}/configs
# ---------------------------------------------------------------------------

class TestCreateAlertConfig:
    def test_503_when_db_disabled(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = False
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("acme-corp")
            resp = client.post("/alerts/acme-corp/configs", json={
                "alert_type": "webhook",
                "endpoint": "https://hooks.example.com/phishing",
            })
            assert resp.status_code == 503
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_401_without_auth(self):
        import db as db_module
        original = _enable_db(db_module)
        try:
            resp = client.post("/alerts/acme-corp/configs", json={
                "alert_type": "webhook",
                "endpoint": "https://hooks.example.com/phishing",
            })
            assert resp.status_code == 401
        finally:
            db_module.DB_ENABLED = original

    def test_403_on_org_mismatch(self):
        import db as db_module
        original = _enable_db(db_module)
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("other-org")
            resp = client.post("/alerts/acme-corp/configs", json={
                "alert_type": "webhook",
                "endpoint": "https://hooks.example.com/phishing",
            })
            assert resp.status_code == 403
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_422_invalid_alert_type(self):
        import db as db_module
        original = _enable_db(db_module)
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("acme-corp")
            resp = client.post("/alerts/acme-corp/configs", json={
                "alert_type": "slack",
                "endpoint": "https://hooks.slack.com/...",
            })
            assert resp.status_code == 422
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_201_creates_webhook_config(self):
        import db as db_module
        original = _enable_db(db_module)
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("acme-corp")
            with patch("db.create_alert_config", AsyncMock(return_value=SAMPLE_CONFIG)):
                resp = client.post("/alerts/acme-corp/configs", json={
                    "alert_type": "webhook",
                    "endpoint": "https://hooks.example.com/phishing",
                })
                assert resp.status_code == 201
                data = resp.json()
                assert data["id"] == 1
                assert data["org_id"] == "acme-corp"
                assert data["alert_type"] == "webhook"
                assert data["endpoint"] == "https://hooks.example.com/phishing"
                assert data["enabled"] is True
                assert isinstance(data["created_at"], str)
                assert isinstance(data["updated_at"], str)
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_201_creates_email_config(self):
        import db as db_module
        original = _enable_db(db_module)
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("acme-corp")
            with patch("db.create_alert_config", AsyncMock(return_value=SAMPLE_EMAIL_CONFIG)):
                resp = client.post("/alerts/acme-corp/configs", json={
                    "alert_type": "email",
                    "endpoint": "security@example.com",
                })
                assert resp.status_code == 201
                data = resp.json()
                assert data["alert_type"] == "email"
                assert data["endpoint"] == "security@example.com"
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# PUT /alerts/{org_id}/configs/{config_id}
# ---------------------------------------------------------------------------

class TestUpdateAlertConfig:
    def test_503_when_db_disabled(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = False
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("acme-corp")
            resp = client.put("/alerts/acme-corp/configs/1", json={"enabled": False})
            assert resp.status_code == 503
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_401_without_auth(self):
        import db as db_module
        original = _enable_db(db_module)
        try:
            resp = client.put("/alerts/acme-corp/configs/1", json={"enabled": False})
            assert resp.status_code == 401
        finally:
            db_module.DB_ENABLED = original

    def test_403_on_org_mismatch(self):
        import db as db_module
        original = _enable_db(db_module)
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("other-org")
            resp = client.put("/alerts/acme-corp/configs/1", json={"enabled": False})
            assert resp.status_code == 403
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_404_when_not_found(self):
        import db as db_module
        original = _enable_db(db_module)
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("acme-corp")
            with patch("db.update_alert_config", AsyncMock(return_value=None)):
                resp = client.put("/alerts/acme-corp/configs/999", json={"enabled": False})
                assert resp.status_code == 404
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_200_updates_enabled_field(self):
        import db as db_module
        original = _enable_db(db_module)
        updated = {**SAMPLE_CONFIG, "enabled": False}
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("acme-corp")
            with patch("db.update_alert_config", AsyncMock(return_value=updated)):
                resp = client.put("/alerts/acme-corp/configs/1", json={"enabled": False})
                assert resp.status_code == 200
                data = resp.json()
                assert data["enabled"] is False
                assert data["id"] == 1
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_200_updates_endpoint_field(self):
        import db as db_module
        original = _enable_db(db_module)
        updated = {**SAMPLE_CONFIG, "endpoint": "https://new.example.com/hook"}
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("acme-corp")
            with patch("db.update_alert_config", AsyncMock(return_value=updated)):
                resp = client.put("/alerts/acme-corp/configs/1", json={
                    "endpoint": "https://new.example.com/hook"
                })
                assert resp.status_code == 200
                data = resp.json()
                assert data["endpoint"] == "https://new.example.com/hook"
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# DELETE /alerts/{org_id}/configs/{config_id}
# ---------------------------------------------------------------------------

class TestDeleteAlertConfig:
    def test_503_when_db_disabled(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = False
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("acme-corp")
            resp = client.delete("/alerts/acme-corp/configs/1")
            assert resp.status_code == 503
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_401_without_auth(self):
        import db as db_module
        original = _enable_db(db_module)
        try:
            resp = client.delete("/alerts/acme-corp/configs/1")
            assert resp.status_code == 401
        finally:
            db_module.DB_ENABLED = original

    def test_403_on_org_mismatch(self):
        import db as db_module
        original = _enable_db(db_module)
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("other-org")
            resp = client.delete("/alerts/acme-corp/configs/1")
            assert resp.status_code == 403
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_404_when_not_found(self):
        import db as db_module
        original = _enable_db(db_module)
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("acme-corp")
            with patch("db.delete_alert_config", AsyncMock(return_value=False)):
                resp = client.delete("/alerts/acme-corp/configs/999")
                assert resp.status_code == 404
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_204_on_success(self):
        import db as db_module
        original = _enable_db(db_module)
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_org("acme-corp")
            with patch("db.delete_alert_config", AsyncMock(return_value=True)):
                resp = client.delete("/alerts/acme-corp/configs/1")
                assert resp.status_code == 204
                assert resp.content == b""
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()
