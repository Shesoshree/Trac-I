"""NLP Sentiment, Emotional Manipulation & Urgency Classification Engine for Trac-I.

Rationale for Architecture:
We utilize a dual-layer NLP architecture:
1. TF-IDF + Calibrated Linear Classifier trained on authentic phishing lures vs benign email corpora.
   - Provides sub-millisecond inference (< 5ms) suitable for high-throughput gateway filtering.
   - Offline, deterministic, zero multi-gigabyte GPU overhead.
   - Complete feature interpretability (XAI) exposing exact n-gram risk contributions.
2. Rule-grounded emotional manipulation lexicon:
   - Evaluates psychological coercion vectors (Urgency, Fear/Disciplinary, Authority Impersonation,
     Credential Solicitation, and BEC Remittance).
   - Extracts precise token spans for interactive analyst triage highlighting.
"""

from __future__ import annotations

import math
import os
import re
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np

# Core emotional & coercive lexicon with sentiment valence weights
COERCIVE_PATTERNS = {
    "urgency": [
        (r"within\s+\d+\s+(?:hours?|days?|minutes?)", 0.85),
        (r"immediate(?:ly)?\s+action\s+required", 0.95),
        (r"immediate\s+response", 0.75),
        (r"final\s+notice", 0.90),
        (r"expires?\s+(?:today|soon|within)", 0.80),
        (r"urgent(?:ly)?\s+update", 0.85),
        (r"deadline\s+is\s+approaching", 0.80),
        (r"time[\s-]sensitive", 0.75),
        (r"must\s+be\s+completed\s+by", 0.70),
        (r"do\s+not\s+ignore", 0.90),
        (r"24\s+hours?\s+remaining", 0.85),
        (r"act\s+now", 0.75),
    ],
    "fear_consequence": [
        (r"account\s+(?:will\s+be\s+)?(?:suspended|terminated|disabled|locked|deleted)", 0.95),
        (r"disciplinary\s+(?:action|review)", 0.90),
        (r"suspension\s+of\s+(?:facility\s+)?access", 0.95),
        (r"revocation\s+of\s+(?:active\s+)?(?:dod\s+)?(?:security\s+tokens?|credentials?)", 0.98),
        (r"unauthorized\s+access\s+detected", 0.85),
        (r"security\s+breach\s+detected", 0.90),
        (r"compliance\s+violation", 0.85),
        (r"legal\s+(?:consequences|action)", 0.90),
        (r"reported\s+to\s+(?:security|ciso|defense|fbi)", 0.88),
        (r"clearance\s+suspension", 0.98),
        (r"penalty\s+applied", 0.80),
    ],
    "authority_pretext": [
        (r"hr\s+(?:department|policy|director|team)", 0.70),
        (r"chief\s+information\s+security\s+officer", 0.85),
        (r"\bciso\b", 0.80),
        (r"global\s+admin(?:istrator)?", 0.80),
        (r"it\s+(?:helpdesk|support|security|services)", 0.75),
        (r"defense\s+security\s+service", 0.90),
        (r"defense\s+contractor\s+compliance", 0.90),
        (r"office\s+of\s+the\s+inspector\s+general", 0.92),
        (r"microsoft\s+365\s+admin", 0.85),
        (r"executive\s+directive", 0.88),
        (r"dcsa\s+compliance", 0.92),
        (r"cmmc\s+2\.0\s+directive", 0.90),
    ],
    "credential_harvesting": [
        (r"verify\s+(?:your\s+)?(?:password|identity|credentials|account)", 0.95),
        (r"update\s+(?:your\s+)?(?:password|credentials|mfa)", 0.90),
        (r"keep\s+your\s+current\s+password", 0.92),
        (r"re[\s-]authenticate", 0.90),
        (r"two[\s-]factor|2fa|mfa", 0.75),
        (r"enter\s+(?:your\s+)?(?:pin|passcode|code|cac)", 0.95),
        (r"sign[\s-]in\s+to\s+confirm", 0.85),
        (r"log[\s-]in\s+to\s+review", 0.85),
        (r"portal\s+login", 0.80),
        (r"cac\s+authentication", 0.85),
    ],
    "bec_financial": [
        (r"urgent\s+wire\s+transfer", 0.95),
        (r"procurement\s+invoice", 0.75),
        (r"bank\s+routing", 0.85),
        (r"remittance\s+advice", 0.80),
        (r"payment\s+overdue", 0.85),
        (r"updated\s+banking\s+details", 0.95),
        (r"confidential\s+acquisition", 0.85),
    ],
}

# Positive / Reassuring tokens common in legitimate communication
BENIGN_AFFIRMATIONS = [
    r"thank\s+you",
    r"have\s+a\s+great\s+weekend",
    r"meeting\s+notes",
    r"project\s+update",
    r"attached\s+slides",
    r"quarterly\s+results",
    r"all[\s-]hands",
    r"optional\s+attendance",
    r"feel\s+free\s+to\s+reach\s+out",
    r"happy\s+to\s+help",
]


class NlpSentimentClassifier:
    """Trained NLP Model & Sentiment Scorer for Phishing Text Intelligence."""

    _vectorizer = None
    _classifier = None
    _model_dir: str = "engine"

    @classmethod
    def load_models(cls, model_dir: str = "engine") -> bool:
        """Load trained scikit-learn TF-IDF vectorizer and classifier from disk."""
        cls._model_dir = model_dir
        vec_path = os.path.join(model_dir, "nlp_vectorizer.joblib")
        clf_path = os.path.join(model_dir, "nlp_classifier.joblib")

        if os.path.exists(vec_path) and os.path.exists(clf_path):
            try:
                cls._vectorizer = joblib.load(vec_path)
                cls._classifier = joblib.load(clf_path)
                return True
            except Exception:
                pass
        return False

    @classmethod
    def predict_phishing_probability(cls, text: str) -> float:
        """Predict continuous probability of text being phishing using trained TF-IDF model."""
        if cls._vectorizer is None or cls._classifier is None:
            if not cls.load_models(cls._model_dir):
                # Fallback to heuristic formula if weights not yet on disk
                return cls._heuristic_text_probability(text)

        try:
            cleaned = text.strip()
            if not cleaned:
                return 0.0
            X = cls._vectorizer.transform([cleaned])
            probs = cls._classifier.predict_proba(X)[0]
            # Class 1 is phishing
            return float(probs[1])
        except Exception:
            return cls._heuristic_text_probability(text)

    @classmethod
    def _heuristic_text_probability(cls, text: str) -> float:
        """Statistical fallback based on coercive token density."""
        text_lower = text.lower()
        score = 0.0
        for category, patterns in COERCIVE_PATTERNS.items():
            for pattern, weight in patterns:
                if re.search(pattern, text_lower):
                    score += weight * 0.25
        for benign_pat in BENIGN_AFFIRMATIONS:
            if re.search(benign_pat, text_lower):
                score -= 0.15
        return float(np.clip(score, 0.0, 1.0))

    @classmethod
    def analyze_text(cls, text: str) -> Dict[str, Any]:
        """Perform comprehensive NLP sentiment, urgency, and psychological coercion analysis."""
        text_lower = text.lower()
        matched_triggers: Dict[str, List[Dict[str, Any]]] = {}
        total_coercive_weight = 0.0
        total_matches = 0

        for category, patterns in COERCIVE_PATTERNS.items():
            matched_triggers[category] = []
            for pattern, weight in patterns:
                for match in re.finditer(pattern, text_lower, re.IGNORECASE):
                    matched_triggers[category].append({
                        "phrase": match.group(0),
                        "weight": weight,
                        "start": match.start(),
                        "end": match.end(),
                    })
                    total_coercive_weight += weight
                    total_matches += 1

        urgency_count = len(matched_triggers["urgency"])
        fear_count = len(matched_triggers["fear_consequence"])
        authority_count = len(matched_triggers["authority_pretext"])
        credential_count = len(matched_triggers["credential_harvesting"])
        bec_count = len(matched_triggers["bec_financial"])

        # Sentiment Valence: Negative (high fear/urgency) to Positive (reassuring/polite)
        benign_matches = 0
        for b_pat in BENIGN_AFFIRMATIONS:
            if re.search(b_pat, text_lower):
                benign_matches += 1

        # Normalized Polarity: -1.0 (Highly Coercive/Threatening) to +1.0 (Benign/Collaborative)
        raw_polarity = (benign_matches * 0.4) - (total_coercive_weight * 0.25)
        sentiment_polarity = float(np.clip(raw_polarity, -1.0, 1.0))

        # ML model prediction probability
        ml_probability = cls.predict_phishing_probability(text)

        # Composite NLP Threat Score (0.0 to 100.0)
        # Combines ML classifier probability (60%) and coercive psychological intensity (40%)
        coercive_ratio = min(1.0, total_coercive_weight / 3.0)
        composite_score = (ml_probability * 60.0) + (coercive_ratio * 40.0)
        composite_score = round(float(np.clip(composite_score, 0.0, 100.0)), 1)

        return {
            "ml_probability": round(ml_probability, 3),
            "nlp_threat_score": composite_score,
            "sentiment_polarity": round(sentiment_polarity, 2),
            "sentiment_label": "Negative / Coercive" if sentiment_polarity < -0.2 else ("Positive / Collaborative" if sentiment_polarity > 0.2 else "Neutral"),
            "matched_triggers": matched_triggers,
            "counts": {
                "urgency": urgency_count,
                "fear": fear_count,
                "authority": authority_count,
                "credential": credential_count,
                "bec": bec_count,
            },
            "total_coercive_triggers": total_matches,
            "has_credential_solicitation": credential_count > 0,
            "has_high_urgency": urgency_count >= 2 or (urgency_count >= 1 and fear_count >= 1),
            "model_architecture": "TF-IDF + Calibrated Classifier with Coercive Lexicon Engine",
        }
