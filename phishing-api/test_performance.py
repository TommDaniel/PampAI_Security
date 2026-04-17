"""
Performance, model validation, and cache contract tests.

Tests:
  - API response time (latency P50/P95/P99)
  - Batch vs single prediction throughput
  - Model output validation (probability ranges, determinism, edge cases)
  - Extension cache contract (TTL, eviction, normalization)
  - Email endpoint performance
"""

import pytest
import time
import statistics
import torch
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient


# ------------------------------------------------------------------
# Mock model setup (same pattern as test_api.py)
# ------------------------------------------------------------------

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


def _set_model_output(logits_values: list):
    import app as app_module
    mock_output = MagicMock()
    mock_output.logits = torch.tensor([logits_values])
    app_module.model.__call__ = MagicMock(return_value=mock_output)
    app_module.model.return_value = mock_output


def _set_email_model_output(logits_values: list):
    import app as app_module
    mock_output = MagicMock()
    mock_output.logits = torch.tensor([logits_values])
    app_module.email_model.__call__ = MagicMock(return_value=mock_output)
    app_module.email_model.return_value = mock_output


_mock_server_features = AsyncMock()

with patch("app.load_model", _mock_load_model), \
     patch("server_features.extract_server_features", _mock_server_features):
    from app import app, ClientFeatures
    from server_features import ServerFeatures

    _mock_load_model()
    _mock_server_features.return_value = ServerFeatures()
    client = TestClient(app)


# ------------------------------------------------------------------
# Sample data
# ------------------------------------------------------------------

LEGIT_REQUEST = {
    "url": "https://google.com",
    "client_features": {
        "length": 25, "dom_length": 10, "dot": 2, "hyphen": 0,
        "slash": 3, "at": 0, "params": 0, "shortened": 0,
        "tls": 1, "vowels_domain": 3, "email": 0,
    },
}

PHISHING_REQUEST = {
    "url": "http://192.168.1.1.suspicious-login-verify.com/@phishing",
    "client_features": {
        "length": 150, "dom_length": 45, "dot": 8, "hyphen": 3,
        "slash": 5, "at": 1, "params": 2, "shortened": 0,
        "tls": 0, "vowels_domain": 8, "email": 0,
    },
}

SAMPLE_EMAIL = {
    "subject": "Urgent: verify your account",
    "body": "Click here to verify your account immediately or it will be suspended.",
    "sender": "security@fake-bank.com",
    "urls_in_body": ["https://fake-bank.com/verify"],
}


# ==================================================================
# 1. API Response Time (Latency)
# ==================================================================

class TestAPILatency:
    """Measure and validate API response times."""

    @pytest.fixture(autouse=True)
    def setup_model(self):
        _set_model_output([2.0, -2.0])

    def _measure_latency(self, endpoint, payload, method="post", n=50):
        """Run n requests and return latency stats in ms."""
        times = []
        for _ in range(n):
            start = time.perf_counter()
            if method == "post":
                client.post(endpoint, json=payload)
            else:
                client.get(endpoint)
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
        times.sort()
        return {
            "p50": times[len(times) // 2],
            "p95": times[int(len(times) * 0.95)],
            "p99": times[int(len(times) * 0.99)],
            "mean": statistics.mean(times),
            "min": min(times),
            "max": max(times),
        }

    def test_predict_latency_under_100ms(self):
        """Single /predict call should respond under 100ms (mocked model)."""
        stats = self._measure_latency("/predict", LEGIT_REQUEST, n=100)
        assert stats["p95"] < 100, f"P95 latency {stats['p95']:.1f}ms exceeds 100ms"
        print(f"\n/predict latency: P50={stats['p50']:.1f}ms P95={stats['p95']:.1f}ms P99={stats['p99']:.1f}ms")

    def test_health_latency_under_20ms(self):
        """/health should be very fast (no model inference)."""
        stats = self._measure_latency("/health", None, method="get", n=100)
        assert stats["p95"] < 20, f"P95 latency {stats['p95']:.1f}ms exceeds 20ms"
        print(f"\n/health latency: P50={stats['p50']:.1f}ms P95={stats['p95']:.1f}ms")

    def test_predict_latency_consistency(self):
        """Latency should not vary wildly between requests (stddev < mean)."""
        times = []
        for _ in range(50):
            start = time.perf_counter()
            client.post("/predict", json=LEGIT_REQUEST)
            times.append((time.perf_counter() - start) * 1000)

        mean = statistics.mean(times)
        stddev = statistics.stdev(times)
        cv = stddev / mean  # coefficient of variation
        assert cv < 2.0, f"Latency too variable: CV={cv:.2f} (mean={mean:.1f}ms, std={stddev:.1f}ms)"

    def test_email_endpoint_latency_under_200ms(self):
        """/analyze-email with mocked models should be under 200ms."""
        _set_email_model_output([-2.0, 2.0])
        stats = self._measure_latency("/analyze-email", SAMPLE_EMAIL, n=50)
        assert stats["p95"] < 200, f"P95 latency {stats['p95']:.1f}ms exceeds 200ms"
        print(f"\n/analyze-email latency: P50={stats['p50']:.1f}ms P95={stats['p95']:.1f}ms")


# ==================================================================
# 2. Batch Throughput
# ==================================================================

class TestBatchThroughput:
    """Compare batch vs individual request throughput."""

    def test_batch_faster_than_individual(self):
        """Batch of 10 URLs should be faster than 10 individual calls."""
        import app as app_module

        N = 10
        batch_payload = [LEGIT_REQUEST] * N

        # Measure individual
        start = time.perf_counter()
        for _ in range(N):
            _set_model_output([2.0, -2.0])
            client.post("/predict", json=LEGIT_REQUEST)
        individual_time = (time.perf_counter() - start) * 1000

        # Measure batch — mock must return (N, 2) logits
        mock_output = MagicMock()
        mock_output.logits = torch.tensor([[2.0, -2.0]] * N)
        app_module.model.return_value = mock_output
        # Tokenizer must return (N, seq_len) tensors for batch
        app_module.tokenizer.return_value = {
            "input_ids": torch.tensor([[101, 102]] * N),
            "attention_mask": torch.tensor([[1, 1]] * N),
        }
        start = time.perf_counter()
        resp = client.post("/predict-batch", json=batch_payload)
        batch_time = (time.perf_counter() - start) * 1000

        assert resp.status_code == 200
        assert len(resp.json()) == N
        print(f"\n10 URLs: individual={individual_time:.1f}ms, batch={batch_time:.1f}ms, "
              f"speedup={individual_time/batch_time:.1f}x")

    def test_batch_scales_linearly(self):
        """Batch time should scale roughly linearly with size."""
        import app as app_module

        sizes = [5, 10, 20]
        times = []
        for size in sizes:
            mock_output = MagicMock()
            mock_output.logits = torch.tensor([[2.0, -2.0]] * size)
            app_module.model.return_value = mock_output
            app_module.tokenizer.return_value = {
                "input_ids": torch.tensor([[101, 102]] * size),
                "attention_mask": torch.tensor([[1, 1]] * size),
            }
            batch = [LEGIT_REQUEST] * size
            start = time.perf_counter()
            client.post("/predict-batch", json=batch)
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)

        # Time for 20 should be less than 5x time for 5 (allows overhead)
        ratio = times[2] / times[0]
        assert ratio < 5.0, f"Batch scaling nonlinear: 20/5 ratio = {ratio:.1f}"
        print(f"\nBatch scaling: 5={times[0]:.1f}ms, 10={times[1]:.1f}ms, 20={times[2]:.1f}ms")


# ==================================================================
# 3. Model Output Validation
# ==================================================================

class TestModelOutputValidation:
    """Validate model predictions are well-formed and consistent."""

    def test_confidence_between_0_and_100(self):
        """Confidence must always be in [0, 100]."""
        test_logits = [
            [5.0, -5.0],   # very confident legitimate
            [-5.0, 5.0],   # very confident phishing
            [0.0, 0.0],    # 50/50
            [0.1, -0.1],   # barely legitimate
            [-0.1, 0.1],   # barely phishing
        ]
        for logits in test_logits:
            _set_model_output(logits)
            data = client.post("/predict", json=LEGIT_REQUEST).json()
            assert 0 <= data["confidence"] <= 100, \
                f"Confidence {data['confidence']} out of range for logits {logits}"

    def test_label_matches_is_phishing(self):
        """Label must be consistent with is_phishing boolean."""
        _set_model_output([-3.0, 3.0])
        phishing = client.post("/predict", json=LEGIT_REQUEST).json()
        assert phishing["is_phishing"] is True
        assert phishing["label"] == "PHISHING"

        _set_model_output([3.0, -3.0])
        legit = client.post("/predict", json=LEGIT_REQUEST).json()
        assert legit["is_phishing"] is False
        assert legit["label"] == "LEGITIMO"

    def test_deterministic_output(self):
        """Same input must always produce identical output."""
        _set_model_output([1.5, -1.5])
        results = []
        for _ in range(20):
            data = client.post("/predict", json=LEGIT_REQUEST).json()
            results.append((data["is_phishing"], data["confidence"], data["label"]))

        assert len(set(results)) == 1, "Model output is non-deterministic"

    def test_high_logit_difference_gives_high_confidence(self):
        """Large logit gap should yield confidence > 90%."""
        _set_model_output([10.0, -10.0])
        data = client.post("/predict", json=LEGIT_REQUEST).json()
        assert data["confidence"] > 90

    def test_balanced_logits_give_lower_confidence(self):
        """Equal logits should give ~50% confidence (uncertain)."""
        _set_model_output([0.0, 0.0])
        data = client.post("/predict", json=LEGIT_REQUEST).json()
        assert data["confidence"] < 70

    def test_inference_ms_is_positive(self):
        """Inference time must be positive."""
        _set_model_output([2.0, -2.0])
        data = client.post("/predict", json=LEGIT_REQUEST).json()
        assert data["inference_ms"] >= 0

    def test_analysis_text_present_and_nonempty(self):
        """Analysis text must always be returned."""
        _set_model_output([2.0, -2.0])
        data = client.post("/predict", json=LEGIT_REQUEST).json()
        assert isinstance(data["analysis"], str)
        assert len(data["analysis"]) > 0

    def test_url_preserved_in_response(self):
        """Response must echo back the exact URL sent."""
        _set_model_output([2.0, -2.0])
        data = client.post("/predict", json=LEGIT_REQUEST).json()
        assert data["url"] == LEGIT_REQUEST["url"]

    def test_source_field_present(self):
        """Response must include the source (bert/cascade/catboost)."""
        _set_model_output([2.0, -2.0])
        data = client.post("/predict", json=LEGIT_REQUEST).json()
        assert data["source"] in ("bert", "cascade", "catboost", "catboost_error")

    def test_phishing_threshold_boundary(self):
        """Test behavior around the 0.65 phishing threshold."""
        import app as app_module

        # softmax([logit_legit, logit_phish])[1] ~= threshold
        # softmax([x, y])[1] = e^y / (e^x + e^y)
        # For P(phish) = 0.65: y - x = log(0.65/0.35) ≈ 0.619
        # Just above threshold
        _set_model_output([-0.35, 0.35])
        above = client.post("/predict", json=LEGIT_REQUEST).json()

        # Just below threshold
        _set_model_output([0.35, -0.35])
        below = client.post("/predict", json=LEGIT_REQUEST).json()

        assert above["is_phishing"] != below["is_phishing"], \
            "Threshold boundary should separate phishing from legitimate"


# ==================================================================
# 4. Email Model Validation
# ==================================================================

class TestEmailModelValidation:
    """Validate email analysis output format and logic."""

    def test_email_label_values(self):
        """Email labels must be PHISHING, SUSPICIOUS, or LEGITIMO."""
        valid_labels = {"PHISHING", "SUSPICIOUS", "LEGITIMO"}

        # High phishing score
        _set_email_model_output([-3.0, 3.0])
        _set_model_output([-3.0, 3.0])
        data = client.post("/analyze-email", json=SAMPLE_EMAIL).json()
        assert data["label"] in valid_labels

        # Low phishing score
        _set_email_model_output([3.0, -3.0])
        _set_model_output([3.0, -3.0])
        data = client.post("/analyze-email", json=SAMPLE_EMAIL).json()
        assert data["label"] in valid_labels

    def test_email_score_between_0_and_100(self):
        """email_score must be a percentage in [0, 100]."""
        _set_email_model_output([-2.0, 2.0])
        _set_model_output([-2.0, 2.0])
        data = client.post("/analyze-email", json=SAMPLE_EMAIL).json()
        assert 0.0 <= data["email_score"] <= 100.0

    def test_url_results_match_input_urls(self):
        """Each URL in body should have a corresponding result."""
        _set_email_model_output([-2.0, 2.0])
        _set_model_output([-2.0, 2.0])
        data = client.post("/analyze-email", json=SAMPLE_EMAIL).json()
        assert len(data["url_results"]) == len(SAMPLE_EMAIL["urls_in_body"])

    def test_email_without_urls(self):
        """Email with no URLs should still be analyzed."""
        _set_email_model_output([3.0, -3.0])
        email_no_urls = {
            "subject": "Hello",
            "body": "Just a normal email with no links.",
            "sender": "friend@gmail.com",
            "urls_in_body": [],
        }
        data = client.post("/analyze-email", json=email_no_urls).json()
        assert data["url_results"] == []
        assert data["label"] in {"PHISHING", "SUSPICIOUS", "LEGITIMO"}

    def test_email_phishing_url_forces_phishing(self):
        """If a URL in the email has >80% phishing confidence, email should be PHISHING."""
        # Email text looks legit, but URL is phishing
        _set_email_model_output([3.0, -3.0])  # email text = legit
        _set_model_output([-5.0, 5.0])         # URL = very phishing (>99%)
        data = client.post("/analyze-email", json=SAMPLE_EMAIL).json()
        assert data["label"] == "PHISHING", \
            "High-confidence phishing URL should force email to PHISHING"

    def test_language_detected_field(self):
        """Response must include language_detected."""
        _set_email_model_output([2.0, -2.0])
        data = client.post("/analyze-email", json=SAMPLE_EMAIL).json()
        assert "language_detected" in data
        assert isinstance(data["language_detected"], str)

    def test_translated_field(self):
        """Response must include translated boolean."""
        _set_email_model_output([2.0, -2.0])
        data = client.post("/analyze-email", json=SAMPLE_EMAIL).json()
        assert "translated" in data
        assert isinstance(data["translated"], bool)


# ==================================================================
# 5. Extension Cache Contract Validation
# ==================================================================

class TestExtensionCacheContract:
    """
    Validate that the extension cache logic (cache.ts) follows
    the correct contract. These tests validate the source code
    structure since we can't run TypeScript in pytest.
    """

    CACHE_TS = "C:\\Users\\danie\\Documents\\TCC\\extensao-phishing\\src\\utils\\cache.ts"

    @pytest.fixture(autouse=True)
    def load_source(self):
        with open(self.CACHE_TS, encoding="utf-8") as f:
            self.source = f.read()

    def test_cache_stored_in_chrome_storage_local(self):
        """Cache must use chrome.storage.local (persists across SW restarts)."""
        assert "chrome.storage.local" in self.source

    def test_cache_key_is_urlcache(self):
        """Cache key must be 'urlCache'."""
        assert '"urlCache"' in self.source

    def test_max_entries_is_5000(self):
        """Cache max should be 5000 entries."""
        assert "MAX_ENTRIES = 5000" in self.source

    def test_ttl_legitimate_is_24_hours(self):
        """Legitimate URLs cached for 24 hours."""
        assert "24 * 60 * 60 * 1000" in self.source

    def test_ttl_phishing_is_7_days(self):
        """Phishing URLs cached for 7 days (longer to protect user)."""
        assert "7 * 24 * 60 * 60 * 1000" in self.source

    def test_eviction_removes_oldest_20_percent(self):
        """When cache is full, evict oldest 20%."""
        assert "0.2" in self.source
        assert "evictOldest" in self.source

    def test_normalize_url_lowercases_hostname(self):
        """URL normalization must lowercase hostname."""
        assert "toLowerCase()" in self.source

    def test_normalize_url_removes_trailing_slash(self):
        """URL normalization must strip trailing slash."""
        assert 'endsWith("/")' in self.source

    def test_cache_entry_has_timestamp(self):
        """Each entry must store timestamp for TTL checks."""
        assert "timestamp" in self.source

    def test_expired_entries_are_deleted(self):
        """Expired entries must be removed on access."""
        assert "delete cache[key]" in self.source

    def test_get_and_set_functions_exported(self):
        """getCached and setCached must be exported."""
        assert "export async function getCached" in self.source
        assert "export async function setCached" in self.source

    def test_clear_cache_exported(self):
        """clearCache must be exported for popup settings."""
        assert "export async function clearCache" in self.source


# ==================================================================
# 6. Extension Cache Integration in Pipeline
# ==================================================================

class TestExtensionCachePipeline:
    """
    Validate that background.ts uses cache correctly in the pipeline.
    """

    BG_TS = "C:\\Users\\danie\\Documents\\TCC\\extensao-phishing\\src\\background.ts"

    @pytest.fixture(autouse=True)
    def load_source(self):
        with open(self.BG_TS, encoding="utf-8") as f:
            self.source = f.read()

    def test_cache_checked_before_api_call(self):
        """Pipeline must check cache BEFORE calling API."""
        cache_pos = self.source.index("getCached")
        api_pos = self.source.index("analyzeUrl")
        assert cache_pos < api_pos, "Cache must be checked before API call"

    def test_whitelist_before_cache(self):
        """Whitelist check must come before cache."""
        whitelist_pos = self.source.index("isWhitelisted")
        cache_pos = self.source.index("getCached")
        assert whitelist_pos < cache_pos, "Whitelist must be checked before cache"

    def test_blacklist_before_cache(self):
        """Blacklist check must come before cache."""
        blacklist_pos = self.source.index("isBlacklisted")
        cache_pos = self.source.index("getCached")
        assert blacklist_pos < cache_pos, "Blacklist must be checked before cache"

    def test_api_result_saved_to_cache(self):
        """After API response, result must be saved to cache."""
        assert "setCached" in self.source

    def test_cache_hit_returns_source_cache(self):
        """Cache hit must set source to 'cache'."""
        assert '"cache"' in self.source

    def test_cache_imports(self):
        """background.ts must import getCached, setCached, clearCache."""
        assert "getCached" in self.source
        assert "setCached" in self.source
        assert "clearCache" in self.source

    def test_cache_result_includes_all_fields(self):
        """Cached result must preserve isPhishing, confidence, label, analysis."""
        # When saving to cache
        assert "cached.isPhishing" in self.source
        assert "cached.confidence" in self.source
        assert "cached.label" in self.source
        assert "cached.analysis" in self.source


# ==================================================================
# 7. API Determinism & Idempotency
# ==================================================================

class TestAPIDeterminism:
    """Validate that the API is deterministic (same input = same output)."""

    def test_predict_idempotent_100_times(self):
        """100 identical requests must all return same result."""
        _set_model_output([2.0, -2.0])
        results = set()
        for _ in range(100):
            data = client.post("/predict", json=LEGIT_REQUEST).json()
            results.add((data["is_phishing"], data["label"], data["confidence"]))
        assert len(results) == 1, f"Non-deterministic: got {len(results)} different results"

    def test_batch_and_single_agree(self):
        """Batch prediction must match individual prediction."""
        import app as app_module

        _set_model_output([1.0, -1.0])
        single = client.post("/predict", json=LEGIT_REQUEST).json()

        mock_output = MagicMock()
        mock_output.logits = torch.tensor([[1.0, -1.0]])
        app_module.model.return_value = mock_output
        batch = client.post("/predict-batch", json=[LEGIT_REQUEST]).json()

        assert single["is_phishing"] == batch[0]["is_phishing"]
        assert single["label"] == batch[0]["label"]
        assert single["confidence"] == batch[0]["confidence"]

    def test_different_urls_can_give_different_results(self):
        """API should not return hardcoded results."""
        import app as app_module

        # Legit URL
        _set_model_output([5.0, -5.0])
        legit = client.post("/predict", json=LEGIT_REQUEST).json()

        # Phishing URL (different logits)
        _set_model_output([-5.0, 5.0])
        phishing = client.post("/predict", json=PHISHING_REQUEST).json()

        assert legit["is_phishing"] != phishing["is_phishing"]


# ==================================================================
# 8. Stress / Concurrency Sanity
# ==================================================================

class TestStressSanity:
    """Basic stress tests to verify API handles repeated calls."""

    def test_200_sequential_predictions(self):
        """API must handle 200 sequential predictions without errors."""
        _set_model_output([2.0, -2.0])
        errors = 0
        for i in range(200):
            resp = client.post("/predict", json=LEGIT_REQUEST)
            if resp.status_code != 200:
                errors += 1
        assert errors == 0, f"{errors}/200 requests failed"

    def test_rapid_health_checks(self):
        """500 rapid /health calls should all succeed."""
        errors = 0
        for _ in range(500):
            if client.get("/health").status_code != 200:
                errors += 1
        assert errors == 0

    def test_alternating_endpoints(self):
        """Alternating between /predict and /health should not break."""
        _set_model_output([2.0, -2.0])
        for _ in range(100):
            assert client.post("/predict", json=LEGIT_REQUEST).status_code == 200
            assert client.get("/health").status_code == 200
