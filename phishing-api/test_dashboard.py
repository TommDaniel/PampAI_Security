"""
Tests for US-009 — Dashboard Backend API endpoints.

Endpoints tested:
- GET /dashboard/{org_id}/events   (paginated event list)
- GET /dashboard/{org_id}/timeline (daily counts for trend chart)

Each endpoint requires authentication (401 anonymous, 403 mismatch, 503 DB disabled).
"""

import pytest
from datetime import datetime, timezone, date
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

SAMPLE_EVENT = {
    "id": 1,
    "org_id": "acme-corp",
    "user_email": None,
    "event_type": "url",
    "url": "http://phishing.example.com",
    "email_subject": None,
    "email_sender": None,
    "is_phishing": True,
    "confidence": 92.5,
    "label": "PHISHING",
    "source": "bert",
    "inference_ms": 45.3,
    "created_at": NOW,
}

SAMPLE_EVENTS_RESULT = {
    "items": [SAMPLE_EVENT],
    "total": 1,
    "page": 1,
    "limit": 20,
}

EMPTY_EVENTS_RESULT = {
    "items": [],
    "total": 0,
    "page": 1,
    "limit": 20,
}

SAMPLE_TIMELINE = [
    {"date": "2026-04-07", "total": 5, "phishing_count": 3, "legitimate_count": 2},
    {"date": "2026-04-08", "total": 8, "phishing_count": 6, "legitimate_count": 2},
    {"date": "2026-04-09", "total": 2, "phishing_count": 1, "legitimate_count": 1},
]


def _mock_get_org_id(org_id):
    """Returns an async function that acts as the get_org_id dependency override."""
    async def _dep():
        return org_id
    return _dep


# ---------------------------------------------------------------------------
# Tests — GET /dashboard/{org_id}/events
# ---------------------------------------------------------------------------

class TestDashboardEventsDbDisabled:
    def test_returns_503_when_db_disabled(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = False
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            response = client.get("/dashboard/acme-corp/events")
            assert response.status_code == 503
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()


class TestDashboardEventsAuth:
    def test_returns_401_without_api_key(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            with patch("db.list_events", AsyncMock(return_value=SAMPLE_EVENTS_RESULT)):
                response = client.get("/dashboard/acme-corp/events")
                assert response.status_code == 401
        finally:
            db_module.DB_ENABLED = original

    def test_returns_403_on_org_mismatch(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("other-org")
            with patch("db.list_events", AsyncMock(return_value=SAMPLE_EVENTS_RESULT)):
                response = client.get("/dashboard/acme-corp/events")
                assert response.status_code == 403
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_returns_200_when_org_matches(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            with patch("db.list_events", AsyncMock(return_value=SAMPLE_EVENTS_RESULT)):
                response = client.get("/dashboard/acme-corp/events")
                assert response.status_code == 200
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()


class TestDashboardEventsResponseSchema:
    def test_response_schema_fields(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            with patch("db.list_events", AsyncMock(return_value=SAMPLE_EVENTS_RESULT)):
                response = client.get("/dashboard/acme-corp/events")
                assert response.status_code == 200
                data = response.json()
                assert "items" in data
                assert "total" in data
                assert "page" in data
                assert "limit" in data
                assert data["total"] == 1
                assert data["page"] == 1
                assert len(data["items"]) == 1
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_event_item_fields(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            with patch("db.list_events", AsyncMock(return_value=SAMPLE_EVENTS_RESULT)):
                response = client.get("/dashboard/acme-corp/events")
                assert response.status_code == 200
                item = response.json()["items"][0]
                assert item["id"] == 1
                assert item["org_id"] == "acme-corp"
                assert item["event_type"] == "url"
                assert item["is_phishing"] is True
                assert item["confidence"] == 92.5
                assert item["label"] == "PHISHING"
                assert item["source"] == "bert"
                assert isinstance(item["created_at"], str)
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_created_at_is_iso_string(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            with patch("db.list_events", AsyncMock(return_value=SAMPLE_EVENTS_RESULT)):
                response = client.get("/dashboard/acme-corp/events")
                item = response.json()["items"][0]
                # Should be parseable as ISO 8601
                datetime.fromisoformat(item["created_at"].replace("Z", "+00:00"))
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_empty_org_returns_zero_total(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            with patch("db.list_events", AsyncMock(return_value=EMPTY_EVENTS_RESULT)):
                response = client.get("/dashboard/acme-corp/events")
                assert response.status_code == 200
                data = response.json()
                assert data["total"] == 0
                assert data["items"] == []
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_pagination_params_forwarded(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            mock_list = AsyncMock(return_value={**EMPTY_EVENTS_RESULT, "page": 2, "limit": 10})
            with patch("db.list_events", mock_list):
                response = client.get("/dashboard/acme-corp/events?page=2&limit=10")
                assert response.status_code == 200
                mock_list.assert_called_once_with(
                    org_id="acme-corp",
                    page=2,
                    limit=10,
                    event_type=None,
                    is_phishing=None,
                    user_email=None,
                )
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_filter_by_event_type_forwarded(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            mock_list = AsyncMock(return_value=EMPTY_EVENTS_RESULT)
            with patch("db.list_events", mock_list):
                client.get("/dashboard/acme-corp/events?event_type=email")
                mock_list.assert_called_once_with(
                    org_id="acme-corp",
                    page=1,
                    limit=20,
                    event_type="email",
                    is_phishing=None,
                    user_email=None,
                )
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Tests — GET /dashboard/{org_id}/timeline
# ---------------------------------------------------------------------------

class TestDashboardTimelineDbDisabled:
    def test_returns_503_when_db_disabled(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = False
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            response = client.get("/dashboard/acme-corp/timeline")
            assert response.status_code == 503
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()


class TestDashboardTimelineAuth:
    def test_returns_401_without_api_key(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            with patch("db.get_timeline", AsyncMock(return_value=SAMPLE_TIMELINE)):
                response = client.get("/dashboard/acme-corp/timeline")
                assert response.status_code == 401
        finally:
            db_module.DB_ENABLED = original

    def test_returns_403_on_org_mismatch(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("other-org")
            with patch("db.get_timeline", AsyncMock(return_value=SAMPLE_TIMELINE)):
                response = client.get("/dashboard/acme-corp/timeline")
                assert response.status_code == 403
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_returns_200_when_org_matches(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            with patch("db.get_timeline", AsyncMock(return_value=SAMPLE_TIMELINE)):
                response = client.get("/dashboard/acme-corp/timeline")
                assert response.status_code == 200
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()


class TestDashboardTimelineResponseSchema:
    def test_response_schema_fields(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            with patch("db.get_timeline", AsyncMock(return_value=SAMPLE_TIMELINE)):
                response = client.get("/dashboard/acme-corp/timeline")
                assert response.status_code == 200
                data = response.json()
                assert data["org_id"] == "acme-corp"
                assert data["days"] == 30
                assert isinstance(data["points"], list)
                assert len(data["points"]) == 3
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_timeline_point_fields(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            with patch("db.get_timeline", AsyncMock(return_value=SAMPLE_TIMELINE)):
                response = client.get("/dashboard/acme-corp/timeline")
                point = response.json()["points"][0]
                assert point["date"] == "2026-04-07"
                assert point["total"] == 5
                assert point["phishing_count"] == 3
                assert point["legitimate_count"] == 2
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_empty_timeline_returns_empty_points(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            with patch("db.get_timeline", AsyncMock(return_value=[])):
                response = client.get("/dashboard/acme-corp/timeline")
                assert response.status_code == 200
                data = response.json()
                assert data["points"] == []
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()

    def test_days_param_forwarded(self):
        import db as db_module
        original = db_module.DB_ENABLED
        db_module.DB_ENABLED = True
        try:
            from app import get_org_id
            app.dependency_overrides[get_org_id] = _mock_get_org_id("acme-corp")
            mock_timeline = AsyncMock(return_value=[])
            with patch("db.get_timeline", mock_timeline):
                response = client.get("/dashboard/acme-corp/timeline?days=7")
                assert response.status_code == 200
                assert response.json()["days"] == 7
                mock_timeline.assert_called_once_with(org_id="acme-corp", days=7)
        finally:
            db_module.DB_ENABLED = original
            app.dependency_overrides.clear()
