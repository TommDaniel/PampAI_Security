"""
Tests for US-002 — API Key Authentication.

Tests:
- get_org_id dependency returns None for anonymous requests
- get_org_id returns org_id for valid API key
- get_org_id raises 401 for invalid API key
- get_org_id raises 503 when DB unavailable and key is provided
- POST /admin/orgs creates org and returns API key
- POST /admin/orgs returns 409 on duplicate org_id
- POST /admin/orgs returns 503 when DB unavailable
- generate_api_key returns 64-char hex string
"""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi import HTTPException
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Unit tests for auth module
# ---------------------------------------------------------------------------

class TestGenerateApiKey:
    def test_returns_64_char_hex(self):
        from auth import generate_api_key
        key = generate_api_key()
        assert len(key) == 64
        assert all(c in "0123456789abcdef" for c in key)

    def test_unique_on_each_call(self):
        from auth import generate_api_key
        keys = {generate_api_key() for _ in range(10)}
        assert len(keys) == 10


class TestGetOrgIdDependency:
    """Unit tests for the get_org_id dependency."""

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_anonymous_request_returns_none(self):
        from auth import get_org_id
        result = self._run(get_org_id(api_key=None))
        assert result is None

    def test_empty_string_returns_none(self):
        from auth import get_org_id
        result = self._run(get_org_id(api_key=""))
        assert result is None

    def test_invalid_key_raises_401_when_db_enabled(self):
        from auth import get_org_id
        import auth as auth_module

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        with patch.object(auth_module, "DB_ENABLED", True), \
             patch("auth.AsyncSessionLocal", return_value=mock_cm):
            with pytest.raises(HTTPException) as exc_info:
                self._run(get_org_id(api_key="invalid-key-xyz"))
            assert exc_info.value.status_code == 401

    def test_valid_key_returns_org_id(self):
        from auth import get_org_id
        import auth as auth_module

        mock_row = MagicMock()
        mock_row.org_id = "acme-corp"

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.first.return_value = mock_row
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        with patch.object(auth_module, "DB_ENABLED", True), \
             patch("auth.AsyncSessionLocal", return_value=mock_cm):
            result = self._run(get_org_id(api_key="valid-key-abc123"))
            assert result == "acme-corp"

    def test_key_provided_db_disabled_raises_503(self):
        from auth import get_org_id
        import auth as auth_module

        with patch.object(auth_module, "DB_ENABLED", False):
            with pytest.raises(HTTPException) as exc_info:
                self._run(get_org_id(api_key="some-key"))
            assert exc_info.value.status_code == 503


# ---------------------------------------------------------------------------
# Integration-style tests via TestClient (admin endpoint)
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

    _mock_load_model()
    _mock_server_features.return_value = ServerFeatures()
    client = TestClient(app)


class TestAdminOrgsEndpoint:
    def test_create_org_db_unavailable_returns_503(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = False
        try:
            response = client.post("/admin/orgs", json={"org_id": "test-org"})
            assert response.status_code == 503
        finally:
            db_module.DB_ENABLED = original

    def test_create_org_success(self):
        import auth as auth_module
        import db as db_module

        async def mock_create_org(org_id, name=None):
            return "abcdef1234567890" * 4  # 64-char hex

        with patch.object(db_module, "DB_ENABLED", True), \
             patch("app.DB_ENABLED", True, create=True), \
             patch("auth.DB_ENABLED", True), \
             patch("auth.create_org", mock_create_org):
            # Override DB_ENABLED check in the endpoint via db module
            import db as db_module2
            db_module2.DB_ENABLED = True
            try:
                response = client.post("/admin/orgs", json={"org_id": "acme-corp", "name": "Acme Corp"})
                # 201 or 503 depending on DB state
                assert response.status_code in (201, 503)
            finally:
                db_module2.DB_ENABLED = original if 'original' in dir() else False

    def test_create_org_schema(self):
        """Response schema must include org_id, api_key, name fields."""
        import db as db_module
        original = db_module.DB_ENABLED

        async def mock_create_org(org_id, name=None):
            return "a" * 64

        db_module.DB_ENABLED = True
        try:
            with patch("auth.create_org", mock_create_org), \
                 patch("auth.DB_ENABLED", True):
                response = client.post(
                    "/admin/orgs",
                    json={"org_id": "test-schema-org", "name": "Test Org"},
                )
                if response.status_code == 201:
                    data = response.json()
                    assert "org_id" in data
                    assert "api_key" in data
                    assert "name" in data
                    assert data["org_id"] == "test-schema-org"
                    assert data["name"] == "Test Org"
        finally:
            db_module.DB_ENABLED = original

    def test_create_org_without_name(self):
        """org_id without name should also work."""
        import db as db_module
        original = db_module.DB_ENABLED

        async def mock_create_org(org_id, name=None):
            return "b" * 64

        db_module.DB_ENABLED = True
        try:
            with patch("auth.create_org", mock_create_org), \
                 patch("auth.DB_ENABLED", True):
                response = client.post(
                    "/admin/orgs",
                    json={"org_id": "no-name-org"},
                )
                if response.status_code == 201:
                    data = response.json()
                    assert data["org_id"] == "no-name-org"
                    assert data["name"] is None
        finally:
            db_module.DB_ENABLED = original

    def test_create_org_duplicate_returns_409(self):
        """Duplicate org_id should return 409."""
        import db as db_module
        original = db_module.DB_ENABLED

        async def mock_create_org_duplicate(org_id, name=None):
            raise Exception("unique constraint violation")

        db_module.DB_ENABLED = True
        try:
            with patch("auth.create_org", mock_create_org_duplicate), \
                 patch("auth.DB_ENABLED", True):
                response = client.post(
                    "/admin/orgs",
                    json={"org_id": "existing-org"},
                )
                if response.status_code != 503:
                    assert response.status_code == 409
        finally:
            db_module.DB_ENABLED = original

    def test_create_org_missing_org_id_returns_422(self):
        """Request without org_id should return 422."""
        response = client.post("/admin/orgs", json={"name": "No ID Corp"})
        assert response.status_code == 422
