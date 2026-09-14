"""Comprehensive test suite verifying all Key Objectives and Security Guards."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.features import (
    HeaderFeatureExtractor,
    UrlFeatureExtractor,
    NlpBodyExtractor,
    extract_all_features_from_email,
)
from engine.domain_lookup import DomainAgeLookup
from engine.nlp_model import NlpSentimentClassifier
from engine.ml_engine import PhishingScoringEngine, extract_feature_vector
from engine.sandbox import SandboxAnalyzer
from engine.security import is_ip_blocked, validate_safe_url, SlidingWindowRateLimiter
from engine.db import ScanDatabase


class TestPipelineComprehensive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scoring_engine = PhishingScoringEngine(model_dir="engine")
        NlpSentimentClassifier.load_models(model_dir="engine")
        ScanDatabase.set_db_path("data/test_scan_history.db")

    # -------------------------------------------------------------
    # 1. Header Feature Extraction (SPF, DKIM, DMARC, Alignment)
    # -------------------------------------------------------------
    def test_headers_pass_authentic(self):
        eml = """From: "Corporate IT" <helpdesk@defenseaerosystems.com>
Return-Path: <helpdesk@defenseaerosystems.com>
Authentication-Results: mx.defense.com; spf=pass client-ip=13.107.6.152; dkim=pass; dmarc=pass
Subject: Standard Maintenance
Content-Type: text/plain

All systems operational.
"""
        extracted = extract_all_features_from_email(eml)
        h = extracted["headers"]
        self.assertEqual(h["spf"]["status"], "pass")
        self.assertEqual(h["dkim"]["status"], "pass")
        self.assertEqual(h["dmarc"]["status"], "pass")
        self.assertFalse(h["mismatches"]["return_path"])
        self.assertFalse(h["mismatches"]["display_name_spoof"])
        self.assertLessEqual(h["header_risk_score"], 15.0)

    def test_headers_spoof_and_mismatch(self):
        eml = """From: "Microsoft 365 Executive Security" <attacker@zero-day-phish.xyz>
Return-Path: <bounce@bulletproof-relay.online>
Reply-To: <dropbox@mailinator.com>
Authentication-Results: mx.defense.com; spf=fail client-ip=194.26.29.112; dkim=fail; dmarc=fail action=quarantine
Subject: Immediate Password Reset Required
Content-Type: text/plain

Your credentials must be verified.
"""
        extracted = extract_all_features_from_email(eml)
        h = extracted["headers"]
        self.assertEqual(h["spf"]["status"], "fail")
        self.assertEqual(h["dkim"]["status"], "fail")
        self.assertEqual(h["dmarc"]["status"], "fail")
        self.assertTrue(h["mismatches"]["return_path"])
        self.assertTrue(h["mismatches"]["reply_to"])
        self.assertTrue(h["mismatches"]["display_name_spoof"])
        self.assertGreaterEqual(h["header_risk_score"], 70.0)

    # -------------------------------------------------------------
    # 2. Cyrillic-for-Latin Homoglyph & Punycode URL Analysis
    # -------------------------------------------------------------
    def test_cyrillic_homograph_detection(self):
        # 'о' is Cyrillic Small Letter O (U+043E) replacing Latin 'o'
        cyrillic_url = "https://login-micr\u043esoft365-verify.com/login"
        u = UrlFeatureExtractor.analyze_single_url(cyrillic_url)
        self.assertGreater(len(u["homoglyphs_detected"]), 0)
        self.assertEqual(u["homoglyphs_detected"][0]["unicode"], "U+043E")
        self.assertEqual(u["homoglyphs_detected"][0]["resembles"], "o")
        self.assertGreaterEqual(u["risk_score"], 45.0)

    def test_punycode_and_entropy_detection(self):
        puny_url = "https://xn--cmmc-d-81a.xyz/auth?user=target"
        u = UrlFeatureExtractor.analyze_single_url(puny_url)
        self.assertTrue(u["is_punycode"])
        self.assertGreaterEqual(u["risk_score"], 40.0)

    # -------------------------------------------------------------
    # 3. Real Domain Age (RDAP / WHOIS / Graceful Fallback)
    # -------------------------------------------------------------
    def test_domain_age_established_baseline(self):
        res = DomainAgeLookup.lookup_domain_age("microsoft.com")
        self.assertFalse(res["is_newly_registered"])
        self.assertGreater(res["age_days"], 5000)
        self.assertEqual(res["risk_score"], 0.0)

    def test_domain_age_unregistered_fallback(self):
        # Fail-secure fallback: non-existent domain receives elevated risk penalty
        res = DomainAgeLookup.lookup_domain_age("nonexistent-test-adversary-domain-9912.xyz")
        self.assertTrue(res["is_newly_registered"])
        self.assertGreaterEqual(res["risk_score"], 35.0)
        self.assertEqual(res["lookup_status"], "lookup_failed_or_unregistered")

    # -------------------------------------------------------------
    # 4. NLP Sentiment & Urgency Classification Model
    # -------------------------------------------------------------
    def test_nlp_threat_classification(self):
        coercive_text = (
            "URGENT: Your account will be suspended within 2 hours. "
            "Immediate action required. Please verify your password and credentials now."
        )
        nlp_res = NlpSentimentClassifier.analyze_text(coercive_text)
        self.assertGreaterEqual(nlp_res["ml_probability"], 0.60)
        self.assertGreaterEqual(nlp_res["nlp_threat_score"], 60.0)
        self.assertLess(nlp_res["sentiment_polarity"], 0.0)
        self.assertTrue(nlp_res["has_credential_solicitation"])

    def test_nlp_benign_classification(self):
        benign_text = (
            "Hi team, please find attached the meeting notes and project update from today's discussion. "
            "Thank you for your hard work, and have a great weekend."
        )
        nlp_res = NlpSentimentClassifier.analyze_text(benign_text)
        self.assertLess(nlp_res["ml_probability"], 0.50)
        self.assertLessEqual(nlp_res["nlp_threat_score"], 35.0)
        self.assertGreater(nlp_res["sentiment_polarity"], 0.0)

    # -------------------------------------------------------------
    # 5. Machine Learning Ensemble Scoring & Confidence Percentage
    # -------------------------------------------------------------
    def test_ml_scoring_confidence_and_xai(self):
        # Malicious sample
        phish_eml = """From: "HR Compliance Directorate" <compliance@dcsa-policy.xyz>
Return-Path: <bounce@bulletproof.cc>
Reply-To: <drop@mailinator.com>
Authentication-Results: spf=fail client-ip=194.26.29.112; dkim=fail; dmarc=fail
Subject: URGENT: Facility Clearance Suspension Notice
Content-Type: text/html

<p>Your DoD clearance token will be suspended within 2 hours. Verify CAC PIN immediately: <a href="https://xn--cmmc-d-81a.xyz/portal">https://defense.gov/verify</a></p>
"""
        extracted = extract_all_features_from_email(phish_eml)
        pred = self.scoring_engine.predict_threat(extracted)

        self.assertGreaterEqual(pred["threat_score"], 75.0)
        self.assertIn(pred["severity"], ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(pred["confidence_percentage"], 70.0)
        self.assertGreater(len(pred["feature_contributions"]), 0)

    # -------------------------------------------------------------
    # 6. SSRF Security Guard
    # -------------------------------------------------------------
    def test_ssrf_guard_blocks_sensitive_ips(self):
        # Loopback
        self.assertTrue(is_ip_blocked("127.0.0.1")[0])
        self.assertTrue(is_ip_blocked("127.0.1.1")[0])
        # Link-local / Cloud metadata
        self.assertTrue(is_ip_blocked("169.254.169.254")[0])
        # Private subnets
        self.assertTrue(is_ip_blocked("10.0.0.1")[0])
        self.assertTrue(is_ip_blocked("172.16.1.1")[0])
        self.assertTrue(is_ip_blocked("192.168.1.1")[0])
        # IPv6 loopback & ULA
        self.assertTrue(is_ip_blocked("::1")[0])
        self.assertTrue(is_ip_blocked("fc00::1")[0])

    def test_ssrf_guard_blocks_localhost_urls(self):
        self.assertFalse(validate_safe_url("http://127.0.0.1:8000/api", resolve_dns=False)[0])
        self.assertFalse(validate_safe_url("http://localhost:8080/", resolve_dns=False)[0])
        self.assertFalse(validate_safe_url("http://169.254.169.254/latest/meta-data/", resolve_dns=False)[0])

    # -------------------------------------------------------------
    # 7. Sandbox Isolation & Wireframe Script Neutralization
    # -------------------------------------------------------------
    def test_sandbox_ssrf_containment(self):
        res = SandboxAnalyzer.generate_sandbox_preview("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(res["is_safe"])
        self.assertEqual(res["target_domain"], "BLOCKED_SSRF_TARGET")
        self.assertIn("SSRF SECURITY GUARD TRIGGERED", res["sandboxed_html"])

    def test_sandbox_wireframe_contains_csp(self):
        res = SandboxAnalyzer.generate_sandbox_preview("https://login-micr\u043esoft365-verify.com/login")
        self.assertIn("Content-Security-Policy", res["sandboxed_html"])
        self.assertIn("default-src 'none'", res["sandboxed_html"])
        self.assertNotIn("<script", res["sandboxed_html"].lower())

    # -------------------------------------------------------------
    # 8. Rate Limiting Middleware
    # -------------------------------------------------------------
    def test_rate_limiter(self):
        rl = SlidingWindowRateLimiter(max_requests=5, window_seconds=2)
        for _ in range(5):
            allowed, _, _ = rl.is_allowed("192.0.2.1")
            self.assertTrue(allowed)
        allowed, _, retry = rl.is_allowed("192.0.2.1")
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)

    # -------------------------------------------------------------
    # 9. Persistence Layer (ScanDatabase)
    # -------------------------------------------------------------
    def test_scan_database_persistence(self):
        pred = {"threat_score": 88.5, "severity": "CRITICAL", "confidence_score": 96.0, "category": "Spear-Phish"}
        saved = ScanDatabase.save_scan("email", "Test Persistence Subject", pred)
        self.assertTrue(saved["id"].startswith("scan-"))

        recent = ScanDatabase.get_recent_scans(limit=5)
        self.assertGreaterEqual(len(recent), 1)
        self.assertEqual(recent[0]["id"], saved["id"])

        detail = ScanDatabase.get_scan_by_id(saved["id"])
        self.assertIsNotNone(detail)
        self.assertEqual(detail["target_name"], "Test Persistence Subject")

        deleted = ScanDatabase.delete_scan(saved["id"])
        self.assertTrue(deleted)


if __name__ == "__main__":
    unittest.main()
