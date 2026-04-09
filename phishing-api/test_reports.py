"""
Tests for US-005 — GET /reports/{org_id}/summary endpoint.

Tests:
- Returns 503 when DB is disabled
- Returns 401 when no API key is provided (anonymous request)
- Returns 403 when authenticated org_id doesn't match path org_id
- Returns 200 with correct summary schema when auth matches
- Returns 200 with zero counts when org has no events
- avg_confidence is None when org has no events
- last_event_at is an ISO string when events exist
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

SUMMARY_WITH_EVENTS = {
    "org_id": "acme-corp",
    "total_events": 10,
    "phishing_count": 6,
    "legitimate_count": 4,
    "url_count": 7,
    "email_count": 3,
    "avg_confidence": 87.45,
    "last_event_at": NOW,
}

SUMMARY_EMPTY = {
    "org_id": "acme-corp",
    "total_events": 0,
    "phishing_count": 0,
    "legitimate_count": 0,
    "url_count": 0,
    "email_count": 0,
    "avg_confidence": None,
    "last_event_at": None,
}


def _mock_get_org_id(org_id: str):
    """Returns an async function that acts as the get_org_id dependency override."""
    async def _dep():
        return org_id
    return _dep


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestReportsSummaryDbDisabled:
    def test_returns_503_when_db_disabled(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = False
        try:
            # Even with auth override, DB disabled takes priority
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            response = client.get("/reports/acme-corp/summary")
            assert response.status_code == 503
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()


class TestReportsSummaryAuth:
    def test_returns_401_without_api_key(self):
        """Anonymous request (no X-API-Key) should get 401."""
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            with patch("db.get_org_summary", AsyncMock(return_value=SUMMARY_WITH_EVENTS)):
                response = client.get("/reports/acme-corp/summary")
                assert response.status_code == 401
        finally:
            db_module.DB_ENABLED = original

    def test_returns_403_when_org_mismatch(self):
        """Authenticated as 'other-org' but requesting 'acme-corp' summary."""
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("other-org")
            with patch("db.get_org_summary", AsyncMock(return_value=SUMMARY_WITH_EVENTS)):
                response = client.get("/reports/acme-corp/summary")
                assert response.status_code == 403
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_returns_200_when_org_matches(self):
        """Authenticated as 'acme-corp' requesting 'acme-corp' summary."""
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            with patch("db.get_org_summary", AsyncMock(return_value=SUMMARY_WITH_EVENTS)):
                response = client.get("/reports/acme-corp/summary")
                assert response.status_code == 200
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()


class TestReportsSummaryResponseSchema:
    def test_summary_schema_fields(self):
        """Response contains all required fields with correct types."""
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            with patch("db.get_org_summary", AsyncMock(return_value=SUMMARY_WITH_EVENTS)):
                response = client.get("/reports/acme-corp/summary")
                assert response.status_code == 200
                data = response.json()
                assert data["org_id"] == "acme-corp"
                assert data["total_events"] == 10
                assert data["phishing_count"] == 6
                assert data["legitimate_count"] == 4
                assert data["url_count"] == 7
                assert data["email_count"] == 3
                assert data["avg_confidence"] == 87.45
                assert isinstance(data["last_event_at"], str)
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_last_event_at_is_iso_string(self):
        """last_event_at should be an ISO 8601 string when present."""
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            with patch("db.get_org_summary", AsyncMock(return_value=SUMMARY_WITH_EVENTS)):
                response = client.get("/reports/acme-corp/summary")
                if response.status_code == 200:
                    data = response.json()
                    last_event_at = data["last_event_at"]
                    assert isinstance(last_event_at, str)
                    assert len(last_event_at) > 0
                    # Verify it's parseable as datetime
                    datetime.fromisoformat(last_event_at.replace("Z", "+00:00"))
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()


class TestReportsSummaryEmptyOrg:
    def test_empty_org_returns_zeros(self):
        """Org with no events should return zero counts and null avg/last."""
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            with patch("db.get_org_summary", AsyncMock(return_value=SUMMARY_EMPTY)):
                response = client.get("/reports/acme-corp/summary")
                assert response.status_code == 200
                data = response.json()
                assert data["total_events"] == 0
                assert data["phishing_count"] == 0
                assert data["legitimate_count"] == 0
                assert data["url_count"] == 0
                assert data["email_count"] == 0
                assert data["avg_confidence"] is None
                assert data["last_event_at"] is None
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()
