"""Unit tests for engine/security.py and engine/domain_lookup.py."""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.security import is_ip_blocked, validate_safe_url, SlidingWindowRateLimiter
from engine.domain_lookup import DomainAgeLookup

class TestSecurityAndDomainAge(unittest.TestCase):
    def test_ssrf_blocking_private_ips(self):
        # Localhost / loopback
        blocked, reason = is_ip_blocked("127.0.0.1")
        self.assertTrue(blocked)
        self.assertIn("Loopback", reason)

        # RFC 1918 subnets
        blocked, _ = is_ip_blocked("10.0.1.5")
        self.assertTrue(blocked)
        blocked, _ = is_ip_blocked("192.168.1.1")
        self.assertTrue(blocked)
        blocked, _ = is_ip_blocked("172.16.0.100")
        self.assertTrue(blocked)

        # Cloud metadata service (169.254.169.254)
        blocked, reason = is_ip_blocked("169.254.169.254")
        self.assertTrue(blocked)
        self.assertIn("metadata", reason.lower())

        # Public IP should not be blocked
        blocked, _ = is_ip_blocked("8.8.8.8")
        self.assertFalse(blocked)

    def test_validate_safe_url(self):
        # Block localhost URL
        safe, msg, _ = validate_safe_url("http://localhost:8080/admin", resolve_dns=False)
        self.assertFalse(safe)

        # Block private IP URL
        safe, msg, _ = validate_safe_url("http://192.168.1.50/secret", resolve_dns=False)
        self.assertFalse(safe)

        # Block cloud metadata URL
        safe, msg, _ = validate_safe_url("http://169.254.169.254/latest/meta-data/", resolve_dns=False)
        self.assertFalse(safe)

        # Block non-http schemes
        safe, msg, _ = validate_safe_url("file:///etc/passwd", resolve_dns=False)
        self.assertFalse(safe)
        safe, msg, _ = validate_safe_url("gopher://127.0.0.1:70", resolve_dns=False)
        self.assertFalse(safe)

    def test_rate_limiter(self):
        limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=2)
        # 3 requests allowed
        self.assertTrue(limiter.is_allowed("analyst-1")[0])
        self.assertTrue(limiter.is_allowed("analyst-1")[0])
        self.assertTrue(limiter.is_allowed("analyst-1")[0])
        # 4th request rejected
        allowed, rem, retry = limiter.is_allowed("analyst-1")
        self.assertFalse(allowed)
        self.assertGreaterEqual(retry, 1)

    def test_domain_age_lookup_baseline(self):
        # Check authoritative baseline
        res = DomainAgeLookup.lookup_domain_age("microsoft.com")
        self.assertGreater(res["age_days"], 10000)
        self.assertFalse(res["is_newly_registered"])
        self.assertEqual(res["risk_score"], 0.0)

    def test_domain_age_lookup_raw_ip(self):
        # Raw IP should be marked as newly registered / high risk
        res = DomainAgeLookup.lookup_domain_age("185.220.101.5")
        self.assertTrue(res["is_ip_host"])
        self.assertEqual(res["risk_score"], 45.0)

    def test_domain_age_fallback(self):
        # Fallback for non-existent / unresolvable domain
        res = DomainAgeLookup._make_fallback_result("unknown-random-phish-domain-123.xyz", "offline test")
        self.assertTrue(res["is_newly_registered"])
        self.assertEqual(res["risk_score"], 35.0)
        self.assertEqual(res["lookup_status"], "lookup_failed_or_unregistered")

if __name__ == "__main__":
    unittest.main()
