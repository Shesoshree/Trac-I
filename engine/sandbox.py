"""Automated Sandboxed Link Preview Engine.

Safely simulates and inspects destination landing pages without executing untrusted client scripts
or allowing credential leakage. Generates visual DOM wireframes and threat overlays.
"""

from typing import Any, Dict, List
from urllib.parse import urlparse
import html

# Pre-analyzed signatures for known phishing campaign lures
MOCK_LANDING_SIGNATURES = {
    "microsoft": {
        "title": "Sign in to your account - Microsoft GCC High",
        "brand": "Microsoft 365 GCC High Tenant",
        "favicon": "microsoft",
        "form_action": "https://collector-node.m365-defense-cloud.com/harvest.php",
        "harvested_fields": ["passwd", "loginfmt", "ctx", "flowToken"],
        "ssl_issuer": "Let's Encrypt Authority X3 (Valid SSL on Fresh Domain)",
        "domain_age": "3 days (Registered 2026-09-11)",
        "ip_geolocation": "Amsterdam, Netherlands (AS204957 Bulwark Hosting)",
        "simulated_html": """
<div class="sandbox-mockup-ms">
    <div class="ms-brand-header">
        <svg class="ms-logo" viewBox="0 0 23 23" width="32" height="32"><path fill="#f25022" d="M1 1h10v10H1z"/><path fill="#00a4ef" d="M1 12h10v10H1z"/><path fill="#7fba00" d="M12 1h10v10H12z"/><path fill="#ffb900" d="M12 12h10v10H12z"/></svg>
        <span class="ms-title">Microsoft</span>
    </div>
    <div class="ms-login-card">
        <h2 class="ms-sign-title">Sign in</h2>
        <div class="ms-subtext">Defense Aero Systems Single Sign-On</div>
        <div class="ms-input-box">
            <span class="ms-input-label">Email, phone, or Skype</span>
            <div class="ms-sim-field ms-filled">s.turner@defenseaerosystems.com</div>
        </div>
        <div class="ms-input-box">
            <span class="ms-input-label">Password (Weaponized Capture Target)</span>
            <div class="ms-sim-field ms-pass-field">&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;</div>
            <span class="ms-warning-badge">WEAPONIZED INPUT</span>
        </div>
        <div class="ms-actions">
            <button class="ms-btn" disabled>Next</button>
        </div>
    </div>
</div>
"""
    },
    "defense": {
        "title": "Defense Counterintelligence Agency - Identity Portal",
        "brand": "DoD Defense Cyber Policy Directorate",
        "favicon": "shield",
        "form_action": "https://xn--cmmc-d-81a.xyz/api/token_steal",
        "harvested_fields": ["edipi", "cac_pin", "ssn_last4", "clearance_code"],
        "ssl_issuer": "cPanel, Inc. Certification Authority",
        "domain_age": "5 days (Registered 2026-09-09)",
        "ip_geolocation": "Seychelles (Offshore Bulletproof Transit)",
        "simulated_html": """
<div class="sandbox-mockup-dod">
    <div class="dod-header">
        <div class="dod-seal-box">&#128737;</div>
        <div>
            <div class="dod-title">DEPARTMENT OF DEFENSE</div>
            <div class="dod-subtitle">Defense Counterintelligence & Security Agency (DCSA)</div>
        </div>
    </div>
    <div class="dod-notice">
        <strong>RESTRICTED ACCESS:</strong> Unauthorized access to this system is punishable under 18 U.S.C. &sect; 1028.
    </div>
    <div class="dod-form">
        <div class="ms-input-box">
            <span class="ms-input-label">DoD EDIPI / CAC Identifier</span>
            <div class="ms-sim-field ms-filled">1092837461</div>
        </div>
        <div class="ms-input-box">
            <span class="ms-input-label">Common Access Card (CAC) PIN</span>
            <div class="ms-sim-field ms-pass-field">&bull;&bull;&bull;&bull;&bull;&bull;</div>
            <span class="ms-warning-badge">CREDENTIAL EXTRACTION</span>
        </div>
        <button class="dod-btn" disabled>Acknowledge & Sign</button>
    </div>
</div>
"""
    },
    "invoice": {
        "title": "Secure Document Cloud - Invoice Download",
        "brand": "Tier-1 Defense Supplier Invoicing",
        "favicon": "document",
        "form_action": "http://185.220.101.5:8080/execute_payload",
        "harvested_fields": ["session_id", "os_fingerprint", "ntlm_hash"],
        "ssl_issuer": "None (Insecure HTTP over Port 8080)",
        "domain_age": "Unknown (Raw IP Address Direct Connection)",
        "ip_geolocation": "St. Petersburg, Russia (Known Rogue Relay)",
        "simulated_html": """
<div class="sandbox-mockup-doc">
    <div class="doc-icon">&#128196;</div>
    <h3>INV-2026-891-Certified.pdf.exe</h3>
    <p class="doc-size">File Size: 4.8 MB &bull; Type: Executable masquerading as PDF</p>
    <div class="doc-alert-bar">
        &#9888; MALICIOUS ATTACHMENT: Double extension (.pdf.exe) with concealed PE header
    </div>
    <div class="doc-actions">
        <button class="doc-btn-blocked" disabled>Execution Blocked by Sandbox</button>
    </div>
</div>
"""
    }
}


class SandboxAnalyzer:
    """Simulates safe virtual sandbox inspection for embedded URLs."""

    @classmethod
    def generate_sandbox_preview(cls, url: str) -> Dict[str, Any]:
        """Generate safe rendering data, certificate inspect, and form harvesting telemetry."""
        url_lower = url.lower()
        parsed = urlparse(url if "://" in url_lower else f"http://{url}")
        domain = parsed.hostname or url

        # Pick appropriate landing profile or default
        profile_key = "microsoft"
        if "cmmc" in url_lower or "policy" in url_lower or "defense" in url_lower:
            profile_key = "defense"
        elif "invoice" in url_lower or "exe" in url_lower or "185.220" in url_lower:
            profile_key = "invoice"
        elif "microsoft" in url_lower or "m365" in url_lower or "login" in url_lower or "oauth" in url_lower:
            profile_key = "microsoft"
        else:
            profile_key = "microsoft"

        profile = MOCK_LANDING_SIGNATURES[profile_key]
        is_safe = ("defenseaerosystems.com" in domain) or ("microsoft.com" in domain and not "verify" in domain and not "online" in domain)

        return {
            "target_url": url,
            "target_domain": domain,
            "is_safe": is_safe,
            "page_title": profile["title"] if not is_safe else f"Official Portal - {domain}",
            "brand_impersonated": profile["brand"] if not is_safe else "Defense Aero Systems Verified",
            "ssl_issuer": profile["ssl_issuer"] if not is_safe else "DigiCert Global Root G2 (Extended Validation)",
            "domain_age": profile["domain_age"] if not is_safe else "12 years (Registered 2014)",
            "ip_geolocation": profile["ip_geolocation"] if not is_safe else "Reston, VA, United States (AWS GovCloud)",
            "form_action": profile["form_action"] if not is_safe else "https://identity.defenseaerosystems.com/auth",
            "harvested_fields": profile["harvested_fields"] if not is_safe else [],
            "sandboxed_html": profile["simulated_html"] if not is_safe else """
<div class="sandbox-mockup-safe">
    <div style="text-align: center; padding: 30px;">
        <div style="font-size: 48px; color: #16a34a;">&#10004;</div>
        <h3 style="color: #16a34a; margin-top: 10px;">Legitimate Enterprise Destination</h3>
        <p style="color: #64748b;">This URL routes to an authentic, authenticated corporate infrastructure with valid certificate alignment.</p>
    </div>
</div>
""",
            "threat_warnings": [
                "Credential harvester login form detected targeting corporate SSO.",
                f"External POST form action redirects stolen credentials to: {profile['form_action']}",
                "Newly registered domain using automated TLS certificate to bypass legacy SEGs.",
                f"Server geolocation ({profile['ip_geolocation']}) does not align with enterprise tenant."
            ] if not is_safe else ["Valid domain alignment with corporate PKI infrastructure."]
        }
