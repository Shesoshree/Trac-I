"""Machine Learning Threat Scoring Engine with Explainable AI (XAI) Feature Attribution.

Combines Header Security, Lexical URL properties, NLP Urgency, and DOM Deception
into an ensemble classifier predicting threat probabilities with granular risk contribution bars.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple
import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier

FEATURE_NAMES = [
    ("f01_spf_fail", "SPF Authentication Failure"),
    ("f02_dkim_fail", "DKIM Signature Missing or Failed"),
    ("f03_dmarc_fail", "DMARC Policy Rejection / Alignment Failure"),
    ("f04_return_path_mismatch", "Return-Path Sender Domain Discrepancy"),
    ("f05_reply_to_mismatch", "Deceptive Reply-To Drop-Box Routing"),
    ("f06_display_name_spoof", "Display Name Brand/Executive Spoofing"),
    ("f07_relay_hop_count", "High-Latency External Relay Hops"),
    ("f08_has_homoglyph_url", "IDN Punycode / Cyrillic Homoglyph in Link"),
    ("f09_has_typosquat_url", "Brand Target Typosquatting / Lookalike"),
    ("f10_max_url_entropy", "Elevated Shannon Entropy (Probable DGA)"),
    ("f11_has_ip_url", "Direct IPv4 Host Link (Bypassing DNS)"),
    ("f12_has_high_risk_tld", "Zero-Reputation High-Risk TLD (.xyz, .top)"),
    ("f13_has_url_shortener", "URL Shortener Relay Obfuscation"),
    ("f14_has_open_redirect", "Open Redirect Exploitation Parameter"),
    ("f15_subdomain_depth", "Excessive Subdomain Depth Stacking"),
    ("f16_anchor_href_mismatch", "Visual Anchor Text vs Href Domain Mismatch"),
    ("f17_external_form_action", "Embedded External Credential Harvest Form"),
    ("f18_hidden_elements_count", "Hidden Anti-Bayes Zero-Font HTML Text"),
    ("f19_urgency_intensity", "High-Pressure Psychological Urgency Phrases"),
    ("f20_fear_threat_score", "Disciplinary / Account Suspension Threat"),
    ("f21_credential_solicitation", "Direct Password / CAC / 2FA Solicitation"),
    ("f22_authority_pretext", "Impersonation of Executive / CISO / Defense Auth"),
    ("f23_bec_financial_score", "Expedited Wire Remittance / Invoice Lure"),
    ("f24_header_risk_score", "Aggregated Email Header Risk Score"),
    ("f25_url_risk_score", "Aggregated Embedded URL Risk Score"),
    ("f26_nlp_threat_score", "NLP Psychological Threat Score"),
    ("f27_html_deception_score", "HTML DOM Deception Score"),
]


def extract_feature_vector(analysis_result: Dict[str, Any]) -> np.ndarray:
    """Convert raw multi-dimensional analysis into normalized numerical feature vector."""
    headers = analysis_result.get("headers", {})
    urls = analysis_result.get("urls", {})
    dom = analysis_result.get("dom", {})
    nlp = analysis_result.get("nlp", {})

    spf_status = headers.get("spf", {}).get("status", "none")
    dkim_status = headers.get("dkim", {}).get("status", "none")
    dmarc_status = headers.get("dmarc", {}).get("status", "none")
    mismatches = headers.get("mismatches", {})
    relay = headers.get("relay", {})

    f01 = 1.0 if spf_status == "fail" else (0.6 if spf_status == "softfail" else (0.2 if spf_status == "none" else 0.0))
    f02 = 1.0 if dkim_status == "fail" else (0.4 if dkim_status == "none" else 0.0)
    f03 = 1.0 if dmarc_status == "fail" else (0.3 if dmarc_status == "none" else 0.0)
    f04 = 1.0 if mismatches.get("return_path", False) else 0.0
    f05 = 1.0 if mismatches.get("reply_to", False) else 0.0
    f06 = 1.0 if mismatches.get("display_name_spoof", False) else 0.0
    f07 = min(1.0, relay.get("hop_count", 0) / 6.0)

    f08 = 1.0 if urls.get("any_homoglyph", False) else 0.0
    f09 = 1.0 if urls.get("any_typosquat", False) else 0.0
    
    # Entropy calculation
    max_entropy = 0.0
    for u in urls.get("urls", []):
        max_entropy = max(max_entropy, u.get("entropy_domain", 0.0))
    f10 = min(1.0, max_entropy / 4.5)

    f11 = 1.0 if urls.get("any_ip_host", False) else 0.0
    f12 = 1.0 if any(u.get("is_high_risk_tld", False) for u in urls.get("urls", [])) else 0.0
    f13 = 1.0 if any(u.get("is_shortener", False) for u in urls.get("urls", [])) else 0.0
    f14 = 1.0 if any(u.get("has_open_redirect", False) for u in urls.get("urls", [])) else 0.0
    
    max_depth = max((u.get("subdomain_depth", 0) for u in urls.get("urls", [])), default=0)
    f15 = min(1.0, max_depth / 3.0)

    f16 = 1.0 if len(dom.get("anchor_mismatches", [])) > 0 else 0.0
    f17 = 1.0 if len(dom.get("external_form_actions", [])) > 0 else 0.0
    f18 = min(1.0, dom.get("hidden_elements_count", 0) / 2.0)

    nlp_counts = nlp.get("counts", {})
    f19 = min(1.0, nlp_counts.get("urgency", 0) / 2.0)
    f20 = min(1.0, nlp_counts.get("fear", 0) / 2.0)
    f21 = 1.0 if nlp.get("has_credential_solicitation", False) else 0.0
    f22 = min(1.0, nlp_counts.get("authority", 0) / 2.0)
    f23 = min(1.0, nlp_counts.get("bec", 0) / 1.0)

    f24 = headers.get("header_risk_score", 0.0) / 100.0
    f25 = urls.get("max_url_risk", 0.0) / 100.0
    f26 = nlp.get("nlp_threat_score", 0.0) / 100.0
    f27 = dom.get("suspicious_html_score", 0.0) / 100.0

    return np.array([
        f01, f02, f03, f04, f05, f06, f07,
        f08, f09, f10, f11, f12, f13, f14, f15,
        f16, f17, f18,
        f19, f20, f21, f22, f23,
        f24, f25, f26, f27
    ], dtype=np.float32)


class PhishingScoringEngine:
    """Production ML ensemble scoring engine with explainability feature breakdown."""

    def __init__(self, model_dir: str = "engine"):
        self.model_dir = model_dir
        self.rf_model: Optional[RandomForestClassifier] = None
        self.gb_model: Optional[GradientBoostingClassifier] = None
        self._ensure_models_trained()

    def _generate_synthetic_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Generate high-fidelity defense contractor phishing and legitimate email feature distributions."""
        np.random.seed(42)
        X_list: List[np.ndarray] = []
        y_list: List[int] = []

        # 1. Critical Spear-Phishing & Zero-Day Scenarios (Class 1) - 150 samples
        for _ in range(150):
            vec = np.zeros(len(FEATURE_NAMES), dtype=np.float32)
            # SPF / DMARC failures
            vec[0] = np.random.choice([1.0, 0.6], p=[0.75, 0.25])  # spf fail
            vec[1] = np.random.choice([1.0, 0.4], p=[0.70, 0.30])  # dkim
            vec[2] = np.random.choice([1.0, 0.3], p=[0.80, 0.20])  # dmarc
            vec[3] = np.random.choice([1.0, 0.0], p=[0.70, 0.30])  # return-path mismatch
            vec[4] = np.random.choice([1.0, 0.0], p=[0.60, 0.40])  # reply-to mismatch
            vec[5] = np.random.choice([1.0, 0.0], p=[0.85, 0.15])  # display name spoof
            vec[6] = np.random.uniform(0.4, 1.0)                   # hops

            # URLs: Homoglyphs & Typosquats
            vec[7] = np.random.choice([1.0, 0.0], p=[0.65, 0.35])  # homoglyphs
            vec[8] = np.random.choice([1.0, 0.0], p=[0.75, 0.25])  # typosquat
            vec[9] = np.random.uniform(0.6, 1.0)                   # entropy
            vec[10] = np.random.choice([1.0, 0.0], p=[0.25, 0.75]) # ip url
            vec[11] = np.random.choice([1.0, 0.0], p=[0.70, 0.30]) # high risk tld
            vec[12] = np.random.choice([1.0, 0.0], p=[0.30, 0.70]) # shortener
            vec[13] = np.random.choice([1.0, 0.0], p=[0.25, 0.75]) # open redirect
            vec[14] = np.random.uniform(0.3, 1.0)                   # subdomain depth

            # DOM
            vec[15] = np.random.choice([1.0, 0.0], p=[0.80, 0.20]) # anchor mismatch
            vec[16] = np.random.choice([1.0, 0.0], p=[0.40, 0.60]) # external form
            vec[17] = np.random.choice([1.0, 0.5, 0.0], p=[0.5, 0.3, 0.2]) # hidden text

            # NLP & Urgency
            vec[18] = np.random.uniform(0.6, 1.0)                   # urgency
            vec[19] = np.random.uniform(0.5, 1.0)                   # fear
            vec[20] = np.random.choice([1.0, 0.0], p=[0.85, 0.15]) # credential solicitation
            vec[21] = np.random.uniform(0.5, 1.0)                   # authority
            vec[22] = np.random.choice([1.0, 0.0], p=[0.30, 0.70]) # bec

            # Aggregates
            vec[23] = np.random.uniform(0.65, 1.0)                  # header risk
            vec[24] = np.random.uniform(0.70, 1.0)                  # url risk
            vec[25] = np.random.uniform(0.60, 1.0)                  # nlp threat
            vec[26] = np.random.uniform(0.40, 0.95)                 # html deception

            X_list.append(vec)
            y_list.append(1)

        # 2. BEC / Financial Procurement Lures (Class 1) - 60 samples
        for _ in range(60):
            vec = np.zeros(len(FEATURE_NAMES), dtype=np.float32)
            vec[0] = np.random.choice([0.6, 0.2])                  # softfail/neutral
            vec[1] = np.random.choice([0.4, 0.0])                  # dkim missing
            vec[2] = np.random.choice([0.3, 0.0])                  # dmarc none
            vec[4] = 1.0                                           # Reply-to drop-box
            vec[5] = 1.0                                           # Display name executive spoof
            vec[10] = np.random.choice([1.0, 0.0], p=[0.5, 0.5])   # Raw IP or attachment host
            vec[18] = np.random.uniform(0.5, 0.9)                  # Urgency
            vec[21] = np.random.uniform(0.6, 1.0)                  # Executive Authority
            vec[22] = np.random.uniform(0.8, 1.0)                  # High BEC Wire
            vec[23] = np.random.uniform(0.5, 0.85)
            vec[24] = np.random.uniform(0.5, 0.85)
            vec[25] = np.random.uniform(0.6, 0.9)
            X_list.append(vec)
            y_list.append(1)

        # 3. Legitimate Enterprise & Defense Internal Communications (Class 0) - 200 samples
        for _ in range(200):
            vec = np.zeros(len(FEATURE_NAMES), dtype=np.float32)
            # SPF / DKIM / DMARC PASS
            vec[0] = 0.0  # pass
            vec[1] = 0.0  # pass
            vec[2] = 0.0  # pass
            vec[3] = 0.0  # aligned return-path
            vec[4] = 0.0  # aligned reply-to
            vec[5] = 0.0  # no display spoof
            vec[6] = np.random.uniform(0.1, 0.4) # standard hops (1-3)

            # Clean URLs
            vec[7] = 0.0  # no homoglyphs
            vec[8] = 0.0  # no typosquats
            vec[9] = np.random.uniform(0.1, 0.35) # natural entropy
            vec[10] = 0.0 # no IP
            vec[11] = 0.0 # corporate TLD (.com, .org, .mil)
            vec[12] = 0.0 # no shorteners
            vec[13] = 0.0 # no open redirects
            vec[14] = np.random.uniform(0.0, 0.25) # shallow subdomains

            # Clean DOM
            vec[15] = 0.0 # anchor matches href
            vec[16] = 0.0 # no external form actions
            vec[17] = 0.0 # no hidden text

            # Clean Tone
            vec[18] = np.random.uniform(0.0, 0.15) # low urgency
            vec[19] = 0.0                         # zero fear/threat
            vec[20] = 0.0                         # no credential solicitation
            vec[21] = np.random.uniform(0.0, 0.3)  # normal corporate authority
            vec[22] = 0.0                         # zero bec

            # Low Aggregates
            vec[23] = np.random.uniform(0.0, 0.12)
            vec[24] = np.random.uniform(0.0, 0.15)
            vec[25] = np.random.uniform(0.0, 0.18)
            vec[26] = np.random.uniform(0.0, 0.10)

            X_list.append(vec)
            y_list.append(0)

        # 4. Borderline / Marketing Newsletters (Class 0 with mild noise) - 50 samples
        for _ in range(50):
            vec = np.zeros(len(FEATURE_NAMES), dtype=np.float32)
            vec[0] = np.random.choice([0.0, 0.2]) # neutral or pass
            vec[1] = 0.0
            vec[2] = 0.0
            vec[6] = np.random.uniform(0.3, 0.6)  # marketing platform relay
            vec[12] = np.random.choice([0.0, 1.0], p=[0.8, 0.2]) # click tracker shortener
            vec[18] = np.random.uniform(0.2, 0.4) # promotional urgency (e.g. "register today")
            vec[23] = np.random.uniform(0.1, 0.3)
            vec[24] = np.random.uniform(0.1, 0.35)
            vec[25] = np.random.uniform(0.15, 0.3)
            X_list.append(vec)
            y_list.append(0)

        X = np.array(X_list, dtype=np.float32)
        y = np.array(y_list, dtype=np.int32)
        return X, y

    def _ensure_models_trained(self):
        """Train and persist ensemble models if not present on disk."""
        rf_path = os.path.join(self.model_dir, "rf_model.joblib")
        gb_path = os.path.join(self.model_dir, "gb_model.joblib")

        if os.path.exists(rf_path) and os.path.exists(gb_path):
            try:
                self.rf_model = joblib.load(rf_path)
                self.gb_model = joblib.load(gb_path)
                return
            except Exception:
                pass

        # Train new models
        X, y = self._generate_synthetic_training_data()
        
        rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
        rf.fit(X, y)

        gb = GradientBoostingClassifier(n_estimators=80, max_depth=4, learning_rate=0.08, random_state=42)
        gb.fit(X, y)

        joblib.dump(rf, rf_path)
        joblib.dump(gb, gb_path)

        self.rf_model = rf
        self.gb_model = gb

    def predict_threat(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ensemble threat probability, severity rating, and explainable feature contributions."""
        features = extract_feature_vector(analysis_result)
        features_2d = features.reshape(1, -1)

        # Ensemble prediction (weighted average between Random Forest and Gradient Boosting)
        rf_prob = float(self.rf_model.predict_proba(features_2d)[0][1])
        gb_prob = float(self.gb_model.predict_proba(features_2d)[0][1])
        
        # Blended probability
        threat_prob = (rf_prob * 0.55) + (gb_prob * 0.45)
        threat_score_pct = round(threat_prob * 100.0, 1)

        # Determine Severity Tier
        if threat_score_pct >= 85.0:
            severity = "CRITICAL"
            category = "CRITICAL SPEAR-PHISHING / ZERO-DAY"
            soc_action = "IMMEDIATE BLOCK: Purge from all mailboxes, revoke user tokens, and isolate endpoint."
            badge_color = "#ff1a35"
        elif threat_score_pct >= 55.0:
            severity = "HIGH"
            category = "MALICIOUS PHISHING ATTACK"
            soc_action = "QUARANTINE & BLOCK: Blacklist sender domain and sinkhole embedded destination URLs."
            badge_color = "#ef4444"
        elif threat_score_pct >= 25.0:
            severity = "MEDIUM"
            category = "SUSPICIOUS / ELEVATED RISK"
            soc_action = "SECURITY TRIAGE: Route email to SOC review and enforce link protection sandbox."
            badge_color = "#dc2626"
        else:
            severity = "LOW"
            category = "BENIGN / VERIFIED SAFE"
            soc_action = "ALLOW: Verified authenticated sender and legitimate enterprise content."
            badge_color = "#ffffff"

        # Compute Explainable AI (XAI) feature impact attribution
        rf_importances = self.rf_model.feature_importances_
        feature_contributions: List[Dict[str, Any]] = []

        for idx, (f_key, f_title) in enumerate(FEATURE_NAMES):
            val = float(features[idx])
            imp = float(rf_importances[idx])
            # Contribution weight is active feature value multiplied by feature importance
            contribution = round(val * imp * 100.0 * 2.8, 1)
            
            if contribution > 1.5:
                feature_contributions.append({
                    "feature_key": f_key,
                    "title": f_title,
                    "value": round(val, 2),
                    "impact_percentage": min(45.0, contribution),
                    "is_critical": contribution >= 15.0 or val >= 0.8,
                })

        # Sort descending by impact
        feature_contributions.sort(key=lambda x: x["impact_percentage"], reverse=True)

        return {
            "threat_score": threat_score_pct,
            "threat_probability": round(threat_prob, 4),
            "severity": severity,
            "category": category,
            "soc_action": soc_action,
            "badge_color": badge_color,
            "rf_confidence": round(rf_prob * 100.0, 1),
            "gb_confidence": round(gb_prob * 100.0, 1),
            "feature_contributions": feature_contributions[:8],  # Top 8 risk factors
            "raw_feature_count": len(FEATURE_NAMES),
        }
