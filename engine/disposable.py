"""Disposable Email & Burner Domain Intelligence Engine.

Identifies throwaway, temporary, disposable, and burner email providers
used by adversaries to evade tracking and spam filters.
"""

from typing import Any, Dict, Optional, Set
import re

# Comprehensive list of popular disposable and burner email domains
DISPOSABLE_DOMAINS: Set[str] = {
    # Well-known temporary & disposable providers
    "mailinator.com", "guerrillamail.com", "guerrillamail.net", "guerrillamail.org", "sharklasers.com",
    "10minutemail.com", "10minutemail.net", "temp-mail.org", "tempmail.com", "tempmail.net",
    "throwawaymail.com", "yopmail.com", "yopmail.net", "yopmail.fr", "cool.fr.nf",
    "dispostable.com", "trashmail.com", "trashmail.net", "trashmail.org", "getairmail.com",
    "getnada.com", "inboxbear.com", "mohmal.com", "burnermail.io", "maildrop.cc",
    "crazymailing.com", "fakemailgenerator.com", "generator.email", "generator.email",
    "mintemail.com", "mytemp.email", "emailondeck.com", "deadaddress.com",
    "binkmail.com", "safetymail.info", "suremail.info", "armyspy.com",
    "cuvox.de", "dayrep.com", "einrot.com", "fleckens.hu", "gustr.com",
    "jourrapide.com", "rhyta.com", "superrito.com", "teleworm.us",
    "chacuo.net", "discard.email", "discardmail.com", "spambog.com",
    "tempinbox.com", "jetable.org", "mailcatch.com", "mailnesia.com",
    "dropmail.me", "mohmal.in", "incognitourl.com", "anonymbox.com",
    "trash-mail.com", "burner.email", "burner.im", "temp-mail.io",
    "mailpoof.com", "tmpmail.net", "tmpmail.org", "guerrillamailblock.com",
    "grr.la", "pokemail.net", "spam4.me", "bccto.me", "chacuo.net",
    "0815.ru", "0-mail.com", "10mail.org", "20minutemail.com", "zippymail.info"
}

# Known free public consumer webmail domains
FREE_WEBMAIL_DOMAINS: Set[str] = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "hotmail.com",
    "outlook.com", "live.com", "msn.com", "icloud.com", "me.com", "mac.com",
    "aol.com", "zoho.com", "mail.com", "gmx.com", "gmx.net",
    "protonmail.com", "proton.me", "tutanota.com", "tuta.io", "fastmail.com"
}

# High-trust government and defense TLDs
GOV_MIL_TLDS: Set[str] = {
    "mil", "gov", "fed.us"
}


class DisposableEmailChecker:
    """Detects disposable, burner, free, or high-trust government email domains."""

    @staticmethod
    def extract_domain(input_text: str) -> str:
        """Extract clean domain from email address or URL or domain string."""
        text = input_text.strip().lower()
        if "@" in text:
            parts = text.split("@")
            return parts[-1].strip("<> /")
        if "://" in text:
            # Parse URL
            match = re.search(r"://([^/:]+)", text)
            if match:
                return match.group(1).strip()
        return text.strip("<> /")

    @classmethod
    def check(cls, email_or_domain: str) -> Dict[str, Any]:
        """Perform comprehensive disposable and trust evaluation."""
        raw_input = email_or_domain.strip()
        domain = cls.extract_domain(raw_input)

        is_disposable = domain in DISPOSABLE_DOMAINS or any(domain.endswith(f".{d}") for d in DISPOSABLE_DOMAINS)
        is_free_webmail = domain in FREE_WEBMAIL_DOMAINS
        
        # Check TLD
        domain_parts = domain.split(".")
        tld = domain_parts[-1] if len(domain_parts) > 1 else ""
        is_gov_mil = tld in GOV_MIL_TLDS

        # Determine Category & Risk
        if is_disposable:
            category = "DISPOSABLE_BURNER"
            trust_level = "VERY LOW (Burner Provider)"
            risk_score = 92.0
            recommendation = "BLOCK & REJECT: Temporary burner inboxes are frequently utilized in credential harvesting, fraud, and anti-forensic evasion."
            explanation = f"Domain '{domain}' is a verified disposable throwaway email provider offering short-lived anonymous mailboxes."
        elif is_gov_mil:
            category = "GOVERNMENT_DEFENSE"
            trust_level = "VERY HIGH (Official .gov/.mil)"
            risk_score = 2.0
            recommendation = "ALLOW WITH VERIFICATION: Official government or military domain. Verify SPF/DKIM authentication to ensure non-spoofed sender."
            explanation = f"Domain '{domain}' utilizes an accredited government/defense top-level domain."
        elif is_free_webmail:
            category = "FREE_CONSUMER_WEBMAIL"
            trust_level = "MEDIUM (Consumer Webmail)"
            risk_score = 45.0
            recommendation = "FLAG IF CLAIMING ENTERPRISE: Free webmail should not be used for corporate defense contracts, HR directives, or wire remittances."
            explanation = f"Domain '{domain}' is a legitimate public consumer webmail provider (not a dedicated corporate email infrastructure)."
        else:
            category = "CORPORATE_CUSTOM_DOMAIN"
            trust_level = "STANDARD (Private/Corporate Domain)"
            risk_score = 15.0
            recommendation = "INSPECT REPUTATION & SPF: Private domain. Check domain registration age and mail authentication records."
            explanation = f"Domain '{domain}' is registered as an independent corporate or private domain."

        return {
            "query": raw_input,
            "domain": domain,
            "is_disposable": is_disposable,
            "is_free_webmail": is_free_webmail,
            "is_gov_mil": is_gov_mil,
            "category": category,
            "trust_level": trust_level,
            "risk_score": risk_score,
            "recommendation": recommendation,
            "explanation": explanation,
            "syntax_valid": bool(re.match(r"^[\w\.-]+\.[a-zA-Z]{2,}$", domain)),
        }
