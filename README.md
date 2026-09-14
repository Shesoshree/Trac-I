# Trac-I: AI-Powered Phishing Intelligence & Threat Triage Engine

[![Automated Tests](https://img.shields.io/badge/tests-40%20passing-brightgreen.svg)](run_tests.py)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](requirements.txt)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141-teal.svg)](app.py)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](Dockerfile)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **Zero-Hour Phishing Detection Beating Static Reputation Feed Lag (24–72h)**  
> Trac-I is an authentic, defense-contractor-grade email security intelligence and detection engine. It performs multi-dimensional feature extraction across raw email headers, lexical and homoglyphic URL properties, domain registration age, and email body sentiment/urgency, scoring threat probabilities using a trained Machine Learning ensemble with calibrated confidence percentages, explainable AI (XAI) attributions, and an isolated virtual sandbox preview.

---

## Key Capabilities & Pipeline Architecture

1. **Multi-Feature Header Forensics (`engine/features.py`)**:
   - RFC 822 raw header parser extracting SPF, DKIM, and DMARC authentication verdicts.
   - Cross-header alignment verification: Sender vs. From domain mismatch, Return-Path mismatch, and executive display-name spoofing detection.
   - Graceful fallback for missing, synthetic, or malformed headers.

2. **Lexical & Heuristic URL Intelligence (`engine/features.py`)**:
   - Zero-dependency detection of **Cyrillic-for-Latin homoglyphs** (e.g., `micrоsoft365-verify.com` using Cyrillic `о` `\u043e`).
   - Punycode decoding (`xn--...`), brand typosquatting distance (Levenshtein metric against curated protected corporate brands), Shannon entropy analysis, and high-risk TLD filtering (`.zip`, `.top`, `.xyz`, etc.).
   - Shortener and open redirect identification.

3. **Real Domain Age Engine (`engine/domain_lookup.py`)**:
   - Real RFC 7480 RDAP and socket WHOIS lookup engine with SQLite local caching (`data/domain_cache.db`).
   - Penalizes zero-day registrations (<30 days = risk 1.0, <180 days = risk 0.6).
   - Authoritative baselines for established domains with fail-secure handling on unresolvable/unregistered hosts.

4. **Dual-Layer NLP Sentiment & Urgency Model (`engine/nlp_model.py`)**:
   - **Layer 1**: Trained statistical text classification model using TF-IDF n-grams (1,2) with Logistic Regression, calibrated to output continuous probability score `f29`.
   - **Layer 2**: Multi-vector coercive psychological trigger lexicon identifying urgency, disciplinary fear, financial wire fraud, and credential solicitation.

5. **29-Signal Machine Learning Scoring Ensemble (`engine/ml_engine.py`)**:
   - Soft-voting ensemble combining `RandomForestClassifier` (100 trees) and `GradientBoostingClassifier` (100 estimators).
   - Calibrated Threat Probability Dial (0–100%) and **Confidence Percentage**.
   - Explainable AI (XAI) attribution quantifying the exact percentage contribution of each feature.
   - Deterministic safety overrides for high-severity homoglyphs and authentication failures.

6. **Air-Gapped Sandbox Link Preview (`engine/sandbox.py`)**:
   - Server-Side Request Forgery (SSRF) guard strictly blocking private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local, and cloud metadata IPs (`169.254.169.254`).
   - Client isolation via `<iframe sandbox="" referrerpolicy="no-referrer">` with strict Content-Security-Policy (`default-src 'none'; script-src 'none'`), disallowing attacker script execution, redirects, and forms.

7. **Persistent SOC Triage Audit Trail (`engine/db.py`)**:
   - Persistent SQLite logging (`data/scan_history.db`) for audit trail and post-incident investigation.
   - One-click export of official Markdown Defense Contractor SOC Incident Reports.

---

## Quick Start (Clean Clone Setup)

### Prerequisites
- Python 3.11 or higher
- Git

### 1. Clone & Setup Virtual Environment
```bash
git clone <repo-url> trac-i
cd trac-i

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# Install pinned dependencies
pip install -r requirements.txt
```

### 2. Configure Environment Variables
```bash
cp .env.example .env
```
Default configuration works out of the box with built-in offline baselines. Optionally configure `WHOIS_API_KEY` for commercial lookup feeds.

### 3. Run Automated Tests
```bash
python run_tests.py
```
Expected output:
```text
======================================================================
Total Tests Run: 40
Successes: 40
Failures: 0
Errors: 0
======================================================================
ALL TESTS PASSED SUCCESSFULLY.
```

### 4. Launch Application
```bash
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser to: **`http://127.0.0.1:8000/scan`**

---

## Docker Deployment

### Run with Docker Compose
```bash
docker-compose up --build -d
```
Access the application at `http://localhost:8000`.

### Run Standalone Docker Container
```bash
docker build -t trac-i:latest .
docker run -d -p 8000:8000 -v trac_data:/app/data --name trac-i-engine trac-i:latest
```

---

## API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/analyze/email` | Full 29-signal analysis on raw RFC 822 email headers and body. |
| `POST` | `/api/analyze/url` | Lexical, homoglyph, entropy, and domain risk analysis on a single link. |
| `POST` | `/api/analyze/text` | NLP sentiment, psychological urgency, and BEC trigger analysis. |
| `POST` | `/api/analyze/sandbox` | SSRF-guarded virtual DOM crawl and CSP-sandboxed wireframe generator. |
| `GET`  | `/api/history` | Retrieve persistent SQLite SOC scan history records. |
| `DELETE` | `/api/history` | Clear persistent SQLite SOC scan history records. |
| `GET`  | `/api/model/metrics` | Retrieve model validation metrics and training parameters. |
| `GET`  | `/api/export/incident/{id}` | Export Markdown-formatted Defense Contractor SOC Incident Ticket. |

---

## Model Training & Dataset Provenance

The ML models are pre-trained and serialized in `engine/`. To retrain models from scratch using the included labeled dataset:
```bash
python scripts/train_models.py
```
- **Dataset**: `data/labeled_phishing_dataset.json` contains 437 curated, labeled examples (238 Phishing, 199 Benign) covering Cyrillic homoglyphs, BEC wire fraud, compromised-account lures, PoW domains, zero-reputation redirectors, and legitimate organizational traffic — including deliberately confusing borderline cases where authentication signals contradict the true label (e.g., valid SPF on a wire-fraud lure, broken SPF on a benign internal notice) so model metrics reflect real-world separation difficulty.
- **Model Metrics (`engine/model_metrics.json`)** — reported with holdout test AND honest 5-fold stratified cross-validation:
  - Holdout Test Accuracy: **100.0%** (88-sample holdout)
  - Random Forest 5-Fold CV Accuracy: **99.31%** (± 0.56%)
  - Random Forest 5-Fold CV ROC-AUC: **0.9998**
  - Gradient Boosting 5-Fold CV Accuracy: **100.0%**
  - Top discriminative features: NLP ML intent probability, NLP threat score, return-path mismatch, aggregated header risk

---

## Project Structure
```text
├── app.py                      # FastAPI application, middleware, security headers & API routes
├── Dockerfile                  # Production container specification
├── docker-compose.yml          # Container orchestration with volume persistence
├── requirements.txt            # Pinned dependency manifest
├── run_tests.py                # Unified test runner
├── .env.example                # Environment variable configuration template
├── data/
│   ├── labeled_phishing_dataset.json # Ground-truth curated training dataset
│   ├── scan_history.db         # Persistent SQLite scan history (auto-created)
│   └── domain_cache.db         # Persistent SQLite RDAP/WHOIS cache (auto-created)
├── engine/
│   ├── features.py             # 29-signal feature extraction pipeline
│   ├── ml_engine.py            # Random Forest + Gradient Boosting ensemble scorer
│   ├── nlp_model.py            # TF-IDF + Logistic Regression text classifier & lexicon
│   ├── domain_lookup.py        # RFC 7480 RDAP & WHOIS domain age engine
│   ├── sandbox.py              # SSRF-guarded dynamic sandbox crawler
│   ├── security.py             # SSRF IP blocker & SlidingWindowRateLimiter
│   ├── db.py                   # SQLite persistence layer for scan history
│   ├── scenarios.py            # Enterprise defense triage scenarios
│   ├── rf_model.joblib         # Serialized Random Forest model
│   ├── gb_model.joblib         # Serialized Gradient Boosting model
│   ├── nlp_classifier.joblib   # Serialized NLP Logistic Regression classifier
│   ├── nlp_vectorizer.joblib   # Serialized TF-IDF vectorizer
│   └── model_metrics.json      # Model performance metrics & training metadata
├── scripts/
│   ├── train_models.py         # End-to-end model training script
│   ├── build_dataset.py        # Dataset compilation script
│   ├── generate_presentation.py# Presentation deck generator (.pptx)
│   └── package_deliverables.py # Source code & deliverables packager
├── static/                     # Web application UI, CSS design tokens & JavaScript
├── tests/                      # Automated test suite (40 comprehensive tests)
└── artifacts/                  # Generated presentation deck & packaged deliverables
```

---

## Defense & Security Standards

- **SSRF Immunity**: Prohibits requests to `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`, and IPv6 equivalents.
- **Client DOM Sandboxing**: Attacker HTML is rendered inside `<iframe sandbox="">` with strict CSP; no attacker scripts, styles, or redirects execute in the analyst's browser session.
- **Input Hardening**: Maximum size enforcement (500KB EML, 2048 chars URL, 50KB text) with structured Pydantic validation.
- **Sliding-Window Rate Limiting**: Protects compute-heavy endpoints against denial-of-service.

---
## Team Members

| Team Member         | Role      |
| ------------------- | --------- |
| *Anushree Sharma*   | Developer |
| *Shreyash*          | Presenter |
| *Aarna Verma*       | Designer  |
| *Aditya Pratap*     | Tester    |

*Team Name:* Noclu3
