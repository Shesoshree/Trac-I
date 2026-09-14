"""Multi-dimensional feature extraction for phishing email detection.

Extracts features from:
1. Raw RFC 822 Email Headers (SPF, DKIM, DMARC, Sender alignment, Relay hops)
2. Embedded URLs (Homoglyphs, Punycode, Typosquatting, Shannon Entropy, TLD risk, Shorteners)
3. Email Body & HTML DOM (Urgency NLP, Deceptive HTML, Anchor-HREF mismatches, Form actions)
"""

from __future__ import annotations

import email
from email import policy
from email.message import EmailMessage
import html
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup

from engine.disposable import DisposableEmailChecker, DISPOSABLE_DOMAINS
from engine.domain_lookup import DomainAgeLookup
from engine.nlp_model import NlpSentimentClassifier
HIGH_VALUE_TARGETS = [
    "microsoft",
    "office365",
    "microsoft365",
    "outlook",
    "sharepoint",
    "onedrive",
    "azure",
    "okta",
    "duomobile",
    "defense",
    "lockheed",
    "northrop",
    "raytheon",
    "boeing",
    "generaldynamics",
    "hrportal",
    "workday",
    "adp",
    "servicenow",
    "cisco",
    "google",
    "intranet",
    "vpn",
]

# Suspicious / high-risk TLDs commonly seen in zero-day bulletproof infrastructure
HIGH_RISK_TLDS = {
    "xyz", "top", "click", "live", "support", "work", "cam", "country",
    "buzz", "rest", "tk", "ml", "ga", "cf", "gq", "site", "online",
    "club", "icu", "monster", "cfd", "sbs", "beauty", "hair"
}

# Known URL shortener domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy"
}

# Confusable Cyrillic / Greek characters that look visually identical to Latin
HOMOGLYPH_MAP = {
    "\u0430": ("a", "Cyrillic Small Letter A"),
    "\u0410": ("A", "Cyrillic Capital Letter A"),
    "\u0441": ("c", "Cyrillic Small Letter Es"),
    "\u0421": ("C", "Cyrillic Capital Letter Es"),
    "\u0435": ("e", "Cyrillic Small Letter Ie"),
    "\u0415": ("E", "Cyrillic Capital Letter Ie"),
    "\u0456": ("i", "Cyrillic Small Letter Byelorussian-Ukrainian I"),
    "\u0406": ("I", "Cyrillic Capital Letter Byelorussian-Ukrainian I"),
    "\u0458": ("j", "Cyrillic Small Letter Je"),
    "\u043e": ("o", "Cyrillic Small Letter O"),
    "\u041e": ("O", "Cyrillic Capital Letter O"),
    "\u0440": ("p", "Cyrillic Small Letter Er"),
    "\u0420": ("P", "Cyrillic Capital Letter Er"),
    "\u0455": ("s", "Cyrillic Small Letter Dze"),
    "\u0445": ("x", "Cyrillic Small Letter Ha"),
    "\u0425": ("X", "Cyrillic Capital Letter Ha"),
    "\u0443": ("y", "Cyrillic Small Letter U"),
    "\u0405": ("S", "Cyrillic Capital Letter Dze"),
    "\u03bf": ("o", "Greek Small Letter Omicron"),
    "\u039f": ("O", "Greek Capital Letter Omicron"),
    "\u03c1": ("p", "Greek Small Letter Rho"),
    "\u039a": ("K", "Greek Capital Letter Kappa"),
    "\u03ba": ("k", "Greek Small Letter Kappa"),
}

# Regex for IPv4 address host
IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")


def calculate_shannon_entropy(text: str) -> float:
    """Calculate the Shannon Entropy of a string."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


class HeaderFeatureExtractor:
    """Extracts and analyzes security features from raw email headers."""

    @staticmethod
    def extract_domain(email_address: str) -> str:
        """Extract clean domain from email address like 'User <user@domain.com>'."""
        if not email_address:
            return ""
        match = re.search(r"[\w\.-]+@([\w\.-]+)", email_address)
        if match:
            return match.group(1).lower().strip()
        parts = email_address.split("@")
        if len(parts) > 1:
            return parts[-1].strip("<> ").lower()
        return ""

    @staticmethod
    def extract_display_name(from_header: str) -> str:
        """Extract the friendly display name from From header."""
        if not from_header:
            return ""
        if "<" in from_header:
            return from_header.split("<")[0].strip("\"' ")
        return ""

    @classmethod
    def analyze_headers(cls, raw_email_or_msg: Any) -> Dict[str, Any]:
        """Parse raw email message or text and extract header security features."""
        if isinstance(raw_email_or_msg, str):
            msg = email.message_from_string(raw_email_or_msg, policy=policy.default)
        else:
            msg = raw_email_or_msg

        from_hdr = msg.get("From", "")
        return_path = msg.get("Return-Path", "")
        reply_to = msg.get("Reply-To", "")
        subject = msg.get("Subject", "")
        date_hdr = msg.get("Date", "")
        msg_id = msg.get("Message-ID", "")
        auth_results = msg.get("Authentication-Results", "")
        rec_spf = msg.get("Received-SPF", "")
        dkim_sig = msg.get("DKIM-Signature", "")
        received_hdrs = msg.get_all("Received", []) or []

        from_domain = cls.extract_domain(from_hdr)
        from_display = cls.extract_display_name(from_hdr)
        return_path_domain = cls.extract_domain(return_path)
        reply_to_domain = cls.extract_domain(reply_to)

        # 1. SPF Analysis
        spf_status = "none"
        spf_ip = ""
        combined_spf = f"{auth_results} {rec_spf}".lower()
        if "spf=pass" in combined_spf or "received-spf: pass" in combined_spf or combined_spf.startswith("pass"):
            spf_status = "pass"
        elif "spf=fail" in combined_spf or "received-spf: fail" in combined_spf or combined_spf.startswith("fail"):
            spf_status = "fail"
        elif "spf=softfail" in combined_spf or "received-spf: softfail" in combined_spf or combined_spf.startswith("softfail"):
            spf_status = "softfail"
        elif "spf=neutral" in combined_spf:
            spf_status = "neutral"

        ip_match = re.search(r"client-ip=([\d\.]+)", combined_spf)
        if ip_match:
            spf_ip = ip_match.group(1)

        # 2. DKIM Analysis
        dkim_status = "none"
        dkim_selector = ""
        combined_dkim = f"{auth_results} {dkim_sig}".lower()
        if "dkim=pass" in combined_dkim:
            dkim_status = "pass"
        elif "dkim=fail" in combined_dkim:
            dkim_status = "fail"
        elif dkim_sig:
            dkim_status = "signed_unverified"

        sel_match = re.search(r"s=([\w\.-]+)", dkim_sig)
        if sel_match:
            dkim_selector = sel_match.group(1)

        # 3. DMARC Analysis
        dmarc_status = "none"
        dmarc_action = "none"
        if "dmarc=pass" in auth_results.lower():
            dmarc_status = "pass"
        elif "dmarc=fail" in auth_results.lower():
            dmarc_status = "fail"
            if "action=reject" in auth_results.lower():
                dmarc_action = "reject"
            elif "action=quarantine" in auth_results.lower():
                dmarc_action = "quarantine"

        # 4. Sender Alignment & Spoofing Indicators
        domain_mismatch_return_path = bool(return_path_domain and from_domain and return_path_domain != from_domain)
        domain_mismatch_reply_to = bool(reply_to_domain and from_domain and reply_to_domain != from_domain)

        # Display name spoofing (e.g. Display Name contains "Microsoft", "HR Support", but domain is freemail or unrelated)
        display_name_spoofed = False
        spoof_targets = ["microsoft", "office365", "hr dept", "security alert", "ciso", "admin", "it support", "defense portal"]
        lower_display = from_display.lower()
        for target in spoof_targets:
            if target in lower_display and target.replace(" ", "") not in from_domain:
                display_name_spoofed = True
                break

        # 5. Received Relay Hops
        hop_count = len(received_hdrs)
        originating_ip = ""
        relay_chain: List[str] = []
        for r_hdr in reversed(received_hdrs):
            relay_chain.append(r_hdr[:140].strip())
            if not originating_ip:
                ip_found = re.search(r"\[([\d\.]+)\]", r_hdr)
                if ip_found:
                    originating_ip = ip_found.group(1)

        # Risk scoring for headers (0 to 100)
        risk_score = 0.0
        flags: List[str] = []

        if spf_status == "fail":
            risk_score += 35.0
            flags.append("SPF Authentication HARD FAIL: Sending IP is not authorized")
        elif spf_status == "softfail":
            risk_score += 20.0
            flags.append("SPF Authentication SOFT FAIL: Suspected unauthorized relay")
        elif spf_status == "none":
            risk_score += 10.0
            flags.append("No SPF verification record found")

        if dkim_status == "fail":
            risk_score += 25.0
            flags.append("DKIM Signature Failure: Message modified in transit or forged")
        elif dkim_status == "none":
            risk_score += 8.0

        if dmarc_status == "fail":
            risk_score += 25.0
            flags.append("DMARC Enforcement Failed: Policy violation")

        if domain_mismatch_return_path:
            risk_score += 20.0
            flags.append(f"Return-Path Domain Mismatch: '{return_path_domain}' vs '{from_domain}'")

        if domain_mismatch_reply_to:
            risk_score += 25.0
            flags.append(f"Deceptive Reply-To Mismatch: Replies route to '{reply_to_domain}'")

        if display_name_spoofed:
            risk_score += 30.0
            flags.append(f"Display Name Spoofing Detected: '{from_display}' does not match '{from_domain}'")

        if hop_count > 6:
            risk_score += 10.0
            flags.append(f"High Relay Hop Count ({hop_count} hops): Suspicious proxy routing")

        # Check for disposable / burner domain usage
        disposable_found_domain = ""
        for d in [from_domain, return_path_domain, reply_to_domain]:
            if d and (d in DISPOSABLE_DOMAINS or any(d.endswith(f".{x}") for x in DISPOSABLE_DOMAINS)):
                disposable_found_domain = d
                break

        is_disposable_sender = bool(disposable_found_domain)
        if is_disposable_sender:
            risk_score += 35.0
            flags.append(f"Disposable / Burner Email Service Detected ('{disposable_found_domain}'): Sender utilizes anonymous throwaway inbox")

        # Check domain age of sender from_domain
        from_domain_age = DomainAgeLookup.lookup_domain_age(from_domain) if from_domain else {}
        fully_authenticated = (spf_status == "pass" and (dkim_status == "pass" or dmarc_status == "pass"))
        if not fully_authenticated:
            if from_domain_age.get("is_newly_registered") or from_domain_age.get("is_young_domain"):
                risk_score += from_domain_age.get("risk_score", 0.0)
                flags.extend(from_domain_age.get("risk_reasons", []))

        risk_score = min(100.0, risk_score)

        return {
            "from": from_hdr,
            "from_display": from_display,
            "from_domain": from_domain,
            "return_path": return_path,
            "return_path_domain": return_path_domain,
            "reply_to": reply_to,
            "reply_to_domain": reply_to_domain,
            "subject": subject,
            "date": date_hdr,
            "message_id": msg_id,
            "spf": {
                "status": spf_status,
                "client_ip": spf_ip,
            },
            "dkim": {
                "status": dkim_status,
                "selector": dkim_selector,
            },
            "dmarc": {
                "status": dmarc_status,
                "action": dmarc_action,
            },
            "mismatches": {
                "return_path": domain_mismatch_return_path,
                "reply_to": domain_mismatch_reply_to,
                "display_name_spoof": display_name_spoofed,
            },
            "relay": {
                "hop_count": hop_count,
                "originating_ip": originating_ip,
                "chain": relay_chain,
            },
            "from_domain_age": from_domain_age,
            "header_risk_score": round(risk_score, 1),
            "header_flags": flags,
        }


class UrlFeatureExtractor:
    """Lexical and heuristic URL analyzer for detecting homoglyphs, typosquatting, entropy, and evasion."""

    @classmethod
    def analyze_single_url(cls, raw_url: str) -> Dict[str, Any]:
        """Perform deep lexical and heuristic inspection on a single URL."""
        url_clean = raw_url.strip()
        parsed = urlparse(url_clean if "://" in url_clean else f"http://{url_clean}")
        
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        scheme = parsed.scheme.lower()
        port = parsed.port

        # 1. Homoglyph and Punycode Detection
        is_punycode = hostname.lower().startswith("xn--") or ".xn--" in hostname.lower()
        decoded_punycode = ""
        if is_punycode:
            try:
                decoded_punycode = hostname.encode("ascii").decode("idna")
            except Exception:
                decoded_punycode = hostname

        homoglyphs_detected: List[Dict[str, Any]] = []
        host_to_scan = decoded_punycode if decoded_punycode else hostname

        for idx, ch in enumerate(host_to_scan):
            if ch in HOMOGLYPH_MAP:
                target_latin, desc = HOMOGLYPH_MAP[ch]
                homoglyphs_detected.append({
                    "char": ch,
                    "unicode": f"U+{ord(ch):04X}",
                    "resembles": target_latin,
                    "description": desc,
                    "position": idx,
                })

        # Confusable sequence 'rn' simulating 'm'
        has_rn_substitution = "rn" in hostname.lower() and "rn" in host_to_scan.lower()
        has_homoglyphs = len(homoglyphs_detected) > 0 or is_punycode or has_rn_substitution

        # 2. Domain & TLD extraction
        domain_parts = hostname.split(".")
        tld = domain_parts[-1].lower() if len(domain_parts) > 1 else ""
        subdomain_depth = max(0, len(domain_parts) - 2)
        is_high_risk_tld = tld in HIGH_RISK_TLDS

        # 3. Direct IP address as host
        is_ip_address = bool(IPV4_REGEX.match(hostname))

        # 4. URL Shortener detection
        is_shortener = hostname.lower() in URL_SHORTENERS

        # 5. Open Redirect parameter detection
        has_open_redirect = False
        redirect_target = ""
        query_params = parse_qs(query)
        for param in ["url", "redirect", "next", "dest", "target", "r", "link", "to"]:
            if param in query_params:
                val = query_params[param][0]
                if val.startswith("http://") or val.startswith("https://") or "//" in val:
                    has_open_redirect = True
                    redirect_target = val
                    break

        # 6. Brand Typosquatting / Target Impersonation
        # Normalize hostname without TLD for matching
        main_domain_label = domain_parts[-2] if len(domain_parts) >= 2 else hostname
        best_match_target = ""
        min_distance = 999
        typosquat_flag = False

        # Also test normalized version with homoglyphs replaced
        normalized_host = host_to_scan.lower()
        for hg in homoglyphs_detected:
            normalized_host = normalized_host.replace(hg["char"], hg["resembles"])

        for target in HIGH_VALUE_TARGETS:
            # Check prefix/suffix hyphen squatting e.g. login-microsoft.com
            if target in hostname.lower() or target in normalized_host:
                # If target is in hostname but hostname is not the legitimate brand domain
                legit_domains = [f"{target}.com", f"{target}.org", f"{target}.net", f"{target}.mil", f"{target}.gov"]
                if not any(hostname.lower() == ld or hostname.lower().endswith(f".{ld}") for ld in legit_domains):
                    typosquat_flag = True
                    best_match_target = target
                    min_distance = 0
                    break

            # Check edit distance
            dist = levenshtein_distance(main_domain_label.lower(), target)
            if dist <= 2 and len(main_domain_label) >= 4 and main_domain_label.lower() != target:
                if dist < min_distance:
                    min_distance = dist
                    best_match_target = target
                    typosquat_flag = True

        # 7. Lexical Entropy & Special Character Density
        entropy_domain = calculate_shannon_entropy(hostname)
        entropy_path = calculate_shannon_entropy(path)
        url_length = len(url_clean)
        num_hyphens = hostname.count("-")
        num_at_symbols = url_clean.count("@")
        num_digits = sum(c.isdigit() for c in hostname)
        digit_ratio = round(num_digits / max(1, len(hostname)), 3)

        # Calculate Individual URL Risk Score (0 - 100)
        risk = 0.0
        reasons: List[str] = []

        if has_homoglyphs:
            risk += 45.0
            reasons.append(f"Homoglyph/IDN Punycode Obfuscation detected ({len(homoglyphs_detected)} confusable characters)")

        if typosquat_flag:
            risk += 35.0
            reasons.append(f"Target Impersonation: Brand typosquatting against '{best_match_target}'")

        if is_ip_address:
            risk += 40.0
            reasons.append("Raw IPv4 Host: URL bypasses domain name resolution")

        if is_high_risk_tld:
            risk += 25.0
            reasons.append(f"High-Risk Zero-Reputation TLD: '.{tld}'")

        if is_shortener:
            risk += 20.0
            reasons.append(f"URL Shortener Relay: '{hostname}' hides actual destination")

        if has_open_redirect:
            risk += 30.0
            reasons.append(f"Open Redirect Exploit: Routes to '{redirect_target}'")

        if entropy_domain > 3.8:
            risk += 15.0
            reasons.append(f"High Domain Shannon Entropy ({entropy_domain}): Probable algorithmically generated domain (DGA)")

        if subdomain_depth >= 3:
            risk += 15.0
            reasons.append(f"Excessive Subdomain Stacking ({subdomain_depth} levels)")

        if num_at_symbols > 0:
            risk += 25.0
            reasons.append("URL contains '@' userinfo credential delimiter evasion")

        if scheme == "http":
            risk += 10.0
            reasons.append("Unencrypted HTTP protocol used for sensitive target")

        if port and port not in (80, 443):
            risk += 15.0
            reasons.append(f"Non-standard HTTP port ({port})")

        # 8. Real Domain Age & Registration Intel
        age_info = DomainAgeLookup.lookup_domain_age(hostname)
        if age_info.get("is_newly_registered") or age_info.get("is_young_domain"):
            risk += age_info.get("risk_score", 0.0)
            reasons.extend(age_info.get("risk_reasons", []))

        risk = min(100.0, risk)

        return {
            "url": url_clean,
            "hostname": hostname,
            "scheme": scheme,
            "tld": tld,
            "path": path,
            "is_punycode": is_punycode,
            "decoded_punycode": decoded_punycode,
            "homoglyphs_detected": homoglyphs_detected,
            "has_rn_substitution": has_rn_substitution,
            "is_high_risk_tld": is_high_risk_tld,
            "is_ip_address": is_ip_address,
            "is_shortener": is_shortener,
            "has_open_redirect": has_open_redirect,
            "redirect_target": redirect_target,
            "typosquat_target": best_match_target if typosquat_flag else None,
            "typosquat_distance": min_distance if typosquat_flag else None,
            "entropy_domain": entropy_domain,
            "entropy_path": entropy_path,
            "subdomain_depth": subdomain_depth,
            "url_length": url_length,
            "digit_ratio": digit_ratio,
            "domain_age_days": age_info.get("age_days"),
            "domain_creation_date": age_info.get("creation_date"),
            "domain_registrar": age_info.get("registrar"),
            "is_newly_registered": age_info.get("is_newly_registered", False),
            "is_young_domain": age_info.get("is_young_domain", False),
            "domain_lookup_status": age_info.get("lookup_status", "unknown"),
            "domain_age_risk": age_info.get("risk_score", 0.0),
            "risk_score": round(risk, 1),
            "risk_reasons": reasons,
        }

    @classmethod
    def analyze_all_urls(cls, urls: List[str]) -> Dict[str, Any]:
        """Inspect all extracted URLs and aggregate feature stats."""
        detailed_urls = [cls.analyze_single_url(u) for u in urls]
        
        max_risk = max((u["risk_score"] for u in detailed_urls), default=0.0)
        avg_risk = sum(u["risk_score"] for u in detailed_urls) / max(1, len(detailed_urls))
        has_homoglyphs = any(len(u["homoglyphs_detected"]) > 0 or u["is_punycode"] for u in detailed_urls)
        has_typosquat = any(u["typosquat_target"] is not None for u in detailed_urls)
        has_ip = any(u["is_ip_address"] for u in detailed_urls)
        any_newly_reg = any(u.get("is_newly_registered", False) for u in detailed_urls)
        min_domain_age = min((u["domain_age_days"] for u in detailed_urls if u.get("domain_age_days") is not None), default=9999)
        max_domain_risk = max((u.get("domain_age_risk", 0.0) for u in detailed_urls), default=0.0)

        return {
            "urls": detailed_urls,
            "total_urls_found": len(urls),
            "max_url_risk": round(max_risk, 1),
            "avg_url_risk": round(avg_risk, 1),
            "any_homoglyph": has_homoglyphs,
            "any_typosquat": has_typosquat,
            "any_ip_host": has_ip,
            "any_newly_registered": any_newly_reg,
            "min_domain_age_days": min_domain_age,
            "max_domain_risk": max_domain_risk,
        }


class NlpBodyExtractor:
    """Analyzes email body text, sentiment, psychological urgency, and deceptive HTML structures."""

    # Psychological triggers grouped by vector
    TRIGGERS = {
        "urgency": [
            r"within\s+\d+\s+(?:hours?|days?|minutes?)",
            r"immediate(?:ly)?\s+action\s+required",
            r"immediate\s+response",
            r"final\s+notice",
            r"expires?\s+(?:today|soon|within)",
            r"urgent(?:ly)?\s+update",
            r"deadline",
            r"action\s+required",
            r"time[\s-]sensitive",
            r"must\s+be\s+completed\s+by",
            r"do\s+not\s+ignore",
        ],
        "fear_consequence": [
            r"account\s+(?:will\s+be\s+)?(?:suspended|terminated|disabled|locked|deleted)",
            r"disciplinary\s+(?:action|review)",
            r"suspension\s+of\s+(?:facility\s+)?access",
            r"revocation\s+of\s+(?:active\s+)?(?:dod\s+)?(?:security\s+tokens?|credentials?)",
            r"unauthorized\s+access\s+detected",
            r"security\s+breach",
            r"loss\s+of\s+(?:facility\s+)?access",
            r"compliance\s+violation",
            r"legal\s+consequences",
            r"reported\s+to\s+(?:security|ciso|defense)",
            r"privileges\s+revoked",
            r"clearance\s+suspension",
        ],
        "authority_pretext": [
            r"hr\s+(?:department|policy|director|team)",
            r"chief\s+information\s+security\s+officer",
            r"ciso",
            r"global\s+admin(?:istrator)?",
            r"it\s+(?:helpdesk|support|security|services)",
            r"defense\s+security\s+service",
            r"defense\s+contractor\s+compliance",
            r"office\s+of\s+the\s+inspector\s+general",
            r"microsoft\s+365\s+admin",
            r"executive\s+directive",
        ],
        "credential_harvesting": [
            r"verify\s+(?:your\s+)?(?:password|identity|credentials|account)",
            r"update\s+(?:your\s+)?(?:password|credentials)",
            r"keep\s+your\s+current\s+password",
            r"re[\s-]authenticate",
            r"two[\s-]factor|2fa|mfa",
            r"enter\s+(?:your\s+)?(?:pin|passcode|code)",
            r"sign[\s-]in\s+to\s+confirm",
            r"log[\s-]in\s+to\s+review",
            r"portal\s+login",
        ],
        "bec_financial": [
            r"urgent\s+wire\s+transfer",
            r"procurement\s+invoice",
            r"bank\s+routing",
            r"remittance\s+advice",
            r"payment\s+overdue",
            r"updated\s+banking\s+details",
        ],
    }

    @classmethod
    def extract_body_and_html(cls, msg: EmailMessage) -> Tuple[str, str]:
        """Extract plain text and HTML body parts from MIME message."""
        plain_text = ""
        html_content = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                if "attachment" in content_disposition:
                    continue
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        text = payload.decode(charset, errors="replace")
                        if content_type == "text/plain" and not plain_text:
                            plain_text = text
                        elif content_type == "text/html" and not html_content:
                            html_content = text
                except Exception:
                    pass
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
                if msg.get_content_type() == "text/html":
                    html_content = text
                else:
                    plain_text = text

        # If plain text is empty, generate from HTML
        if not plain_text and html_content:
            soup = BeautifulSoup(html_content, "html.parser")
            plain_text = soup.get_text(separator=" ", strip=True)

        return plain_text, html_content

    @classmethod
    def analyze_html_dom(cls, html_content: str) -> Dict[str, Any]:
        """Analyze HTML DOM structure for deceptive phishing techniques."""
        if not html_content:
            return {
                "hidden_elements_count": 0,
                "anchor_mismatches": [],
                "external_form_actions": [],
                "iframe_count": 0,
                "suspicious_html_score": 0.0,
            }

        soup = BeautifulSoup(html_content, "html.parser")
        hidden_elements: List[str] = []

        # 1. Zero-font / hidden text inspection
        for tag in soup.find_all(style=True):
            style_attr = tag.get("style", "").lower()
            if any(k in style_attr for k in [
                "font-size:0", "font-size: 0", "font-size: 1px",
                "display:none", "display: none", "visibility:hidden", "visibility: hidden",
                "color:transparent", "color: transparent"
            ]):
                hidden_elements.append(tag.get_text(strip=True)[:60])

        # 2. Anchor text vs href mismatch inspection
        # (e.g. text says "https://login.microsoftonline.com" but href is "http://evil.xyz")
        anchor_mismatches: List[Dict[str, str]] = []
        for a_tag in soup.find_all("a", href=True):
            anchor_text = a_tag.get_text(strip=True)
            href = a_tag["href"].strip()
            
            # If anchor text looks like a URL or domain
            if ("http://" in anchor_text or "https://" in anchor_text or ".com" in anchor_text or ".mil" in anchor_text):
                parsed_text = urlparse(anchor_text if "://" in anchor_text else f"http://{anchor_text}")
                parsed_href = urlparse(href if "://" in href else f"http://{href}")
                
                text_host = (parsed_text.hostname or "").lower()
                href_host = (parsed_href.hostname or "").lower()
                
                if text_host and href_host and text_host != href_host:
                    anchor_mismatches.append({
                        "displayed_text": anchor_text,
                        "actual_href": href,
                        "displayed_domain": text_host,
                        "destination_domain": href_host,
                    })

        # 3. External Form Actions (Credential Harvesters)
        external_forms: List[str] = []
        for form in soup.find_all("form", action=True):
            action = form["action"]
            if action.startswith("http://") or action.startswith("https://"):
                external_forms.append(action)

        # 4. Iframes
        iframes = soup.find_all("iframe")

        # HTML deception score
        html_score = 0.0
        if hidden_elements:
            html_score += 35.0
        if anchor_mismatches:
            html_score += 40.0
        if external_forms:
            html_score += 45.0
        if iframes:
            html_score += 25.0

        return {
            "hidden_elements_count": len(hidden_elements),
            "hidden_samples": hidden_elements[:3],
            "anchor_mismatches": anchor_mismatches,
            "external_form_actions": external_forms,
            "iframe_count": len(iframes),
            "suspicious_html_score": min(100.0, html_score),
        }

    @classmethod
    def analyze_text_nlp(cls, text: str) -> Dict[str, Any]:
        """Analyze text for emotional sentiment, urgency, and psychological coercion."""
        return NlpSentimentClassifier.analyze_text(text)


def extract_all_features_from_email(raw_eml_content: str) -> Dict[str, Any]:
    """Master feature extractor: parses raw email, extracts headers, URLs, NLP body, and DOM."""
    msg = email.message_from_bytes(raw_eml_content.encode("utf-8", errors="replace"), policy=policy.default)
    
    # 1. Header features
    header_analysis = HeaderFeatureExtractor.analyze_headers(msg)

    # 2. Body & HTML extraction
    plain_text, html_content = NlpBodyExtractor.extract_body_and_html(msg)

    # 3. URL extraction (from HTML hrefs and plain text URLs)
    extracted_urls: Set[str] = set()
    if html_content:
        soup = BeautifulSoup(html_content, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith("http://") or href.startswith("https://"):
                extracted_urls.add(href)

    # Regex search for URLs in plain text
    url_pattern = re.compile(r"https?://[^\s<>\"'()]+")
    for u in url_pattern.findall(plain_text):
        extracted_urls.add(u.rstrip(".,;!"))

    # 4. URL analysis
    url_analysis = UrlFeatureExtractor.analyze_all_urls(list(extracted_urls))

    # 5. DOM & NLP analysis
    dom_analysis = NlpBodyExtractor.analyze_html_dom(html_content)
    nlp_analysis = NlpBodyExtractor.analyze_text_nlp(plain_text)

    return {
        "headers": header_analysis,
        "urls": url_analysis,
        "dom": dom_analysis,
        "nlp": nlp_analysis,
        "plain_text_snippet": plain_text[:600],
        "html_content": html_content,
    }
