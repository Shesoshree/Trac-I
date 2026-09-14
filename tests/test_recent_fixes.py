"""Regression tests for recent fixes: scheme validation, sandbox honesty,
history deletion, and dataset realism."""
import json
import os
import sys
import unittest
from unittest.mock import patch
from urllib.error import URLError

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from app import app

client = TestClient(app)


class TestSchemeValidation(unittest.TestCase):
    """Verify javascript:, data:, file: schemes are rejected on /api/analyze/url."""

    def test_javascript_scheme_rejected(self):
        resp = client.post("/api/analyze/url", json={"url": "javascript:alert(1)"})
        self.assertEqual(resp.status_code, 400)

    def test_data_scheme_rejected(self):
        resp = client.post(
            "/api/analyze/url", json={"url": "data:text/html,<h1>phish</h1>"}
        )
        self.assertEqual(resp.status_code, 400)

    def test_file_scheme_rejected(self):
        resp = client.post(
            "/api/analyze/url", json={"url": "file:///etc/passwd"}
        )
        self.assertEqual(resp.status_code, 400)

    def test_http_scheme_accepted(self):
        resp = client.post("/api/analyze/url", json={"url": "http://example.com"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("risk_score", resp.json())

    def test_https_scheme_accepted(self):
        resp = client.post("/api/analyze/url", json={"url": "https://example.com"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("risk_score", resp.json())


class TestSandboxOfflineHonesty(unittest.TestCase):
    """When crawl fails the sandbox must not fabricate form/harvest telemetry."""

    @patch("engine.sandbox.urllib.request.urlopen", side_effect=URLError("timeout"))
    def test_offline_report(self, _mock):
        resp = client.post(
            "/api/analyze/sandbox",
            json={"url": "http://unreachable-host-12345.example/login"},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn(body["crawl_status"], ("offline_or_filtered",))
        self.assertTrue(
            body["form_action"] in ("", "None detected"),
            f"form_action should be empty for offline host, got {body['form_action']!r}",
        )
        self.assertEqual(body["harvested_fields"], [])
        self.assertFalse(body.get("has_credential_inputs", True))


class TestDeleteHistoryEndpoint(unittest.TestCase):
    """DELETE /api/history returns 200 with correct structure."""

    def test_clear_all_history(self):
        resp = client.delete("/api/history")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("status", body)
        self.assertEqual(body["status"], "cleared")

    def test_delete_nonexistent_scan_returns_404(self):
        resp = client.delete("/api/history/scan-nonexistent-id")
        self.assertEqual(resp.status_code, 404)

    def test_delete_single_scan_lifecycle(self):
        scan_resp = client.post(
            "/api/analyze/url", json={"url": "https://example.com"}
        )
        scan_id = scan_resp.json().get("scan_id")
        self.assertIsNotNone(scan_id)

        del_resp = client.delete(f"/api/history/{scan_id}")
        self.assertEqual(del_resp.status_code, 200)
        self.assertEqual(del_resp.json()["status"], "deleted")
        self.assertEqual(del_resp.json()["id"], scan_id)


class TestDatasetRealism(unittest.TestCase):
    """Verify labeled_phishing_dataset.json quality constraints."""

    @classmethod
    def setUpClass(cls):
        path = os.path.join(
            os.path.dirname(__file__), "..", "data", "labeled_phishing_dataset.json"
        )
        with open(path, "r", encoding="utf-8") as f:
            cls.dataset = json.load(f)

    def test_minimum_sample_count(self):
        self.assertGreaterEqual(len(self.dataset), 300)

    def test_both_labels_present(self):
        labels = {s["label"] for s in self.dataset}
        self.assertIn(0, labels)
        self.assertIn(1, labels)

    def test_borderline_samples_exist(self):
        spf_pass_phishing = any(
            s.get("label") == 1 and "spf=pass" in s.get("auth_results", "")
            for s in self.dataset
        )
        spf_fail_benign = any(
            s.get("label") == 0
            and (
                "spf=fail" in s.get("auth_results", "")
                or "spf=softfail" in s.get("auth_results", "")
            )
            for s in self.dataset
        )
        self.assertTrue(
            spf_pass_phishing or spf_fail_benign,
            "Need at least one borderline sample: "
            "spf=pass with label=1 or spf=fail/softfail with label=0",
        )


if __name__ == "__main__":
    unittest.main()
