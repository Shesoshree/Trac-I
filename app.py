"""FastAPI Web Application & REST API Server for Trac-I.

Serves:
1. Public Web Experience (Home, Extension Showcase, How It Works)
2. Interactive AI Phishing & Scam Triage Console (/scan)
3. Full REST API for Email Header, URL Homoglyph, NLP Urgency, and ML Threat Scoring
4. Extension Download & In-Browser Extension Simulator
"""

import os
import json
from typing import Any, Dict, Optional
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from engine.customizer import CustomProfileManager, ThreatProfileModel, CustomScenarioRequest
from engine.db import ScanDatabase
from engine.disposable import DisposableEmailChecker
from engine.features import (
    HeaderFeatureExtractor,
    NlpBodyExtractor,
    UrlFeatureExtractor,
    extract_all_features_from_email,
)
from engine.ml_engine import PhishingScoringEngine
from engine.sandbox import SandboxAnalyzer
from engine.scenarios import get_all_scenarios, get_scenario_by_id
from engine.security import SlidingWindowRateLimiter, validate_safe_url

app = FastAPI(
    title="Trac-I - AI Scam & Phishing Detection Platform",
    description="Advanced AI detection engine for phishing emails, homoglyph URLs, and social engineering.",
    version="1.0.0",
)

# Enable CORS for Chrome Extension integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate Limiter & Security Headers Middleware
rate_limiter = SlidingWindowRateLimiter(max_requests=120, window_seconds=60)

@app.middleware("http")
async def security_and_rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path

    # Apply rate limiting to analysis endpoints
    if path.startswith("/api/analyze"):
        allowed, remaining, retry_after = rate_limiter.is_allowed(client_ip)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Please wait before submitting more scans.", "retry_after": retry_after},
                headers={"Retry-After": str(retry_after)}
            )

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# Initialize ML Scoring Engine
scoring_engine = PhishingScoringEngine(model_dir="engine")

# Mount static directory
os.makedirs("static", exist_ok=True)
os.makedirs("static/css", exist_ok=True)
os.makedirs("static/js", exist_ok=True)
os.makedirs("static/downloads", exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/extension-files", StaticFiles(directory="extension"), name="extension-files")


# Pydantic Request Models with Input Validation
class UrlScanRequest(BaseModel):
    url: str = Field(..., max_length=2048, description="Target URL for lexical and heuristic inspection")


class TextScanRequest(BaseModel):
    text: str = Field(..., max_length=50000, description="SMS, BEC, or email body text")


class EmailScanRequest(BaseModel):
    raw_eml: str = Field(..., max_length=500000, description="Raw RFC 822 email payload including headers")


class SandboxRequest(BaseModel):
    url: str = Field(..., max_length=2048, description="Destination URL for isolated virtual DOM inspection")


class DisposableCheckRequest(BaseModel):
    email_or_domain: str = Field(..., max_length=256, description="Email address or domain to check")


# ==========================================
# Web Page Routes
# ==========================================

@app.get("/", response_class=HTMLResponse)
async def home_page():
    """Render Trac-I Home Page."""
    path = os.path.join("static", "index.html")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>Trac-I</h1><p><a href='/scan'>Go to Scanner</a></p>")


@app.get("/extension", response_class=HTMLResponse)
async def extension_page():
    """Render Trac-I Chrome Extension Page with Simulator."""
    path = os.path.join("static", "extension.html")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>Trac-I Extension</h1>")


@app.get("/scan", response_class=HTMLResponse)
async def scan_page():
    """Render Trac-I Interactive AI Scanner & Triage Console."""
    path = os.path.join("static", "scan.html")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>Trac-I Scanner</h1>")


@app.get("/disposable", response_class=HTMLResponse)
async def disposable_page():
    """Render Disposable Email & Burner Domain Checker."""
    path = os.path.join("static", "disposable.html")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>Disposable Email Checker</h1>")


@app.get("/customize", response_class=HTMLResponse)
async def customize_page():
    """Render Custom Threat Profile & Defense Scenario Studio."""
    path = os.path.join("static", "customize.html")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>Threat Profile Customization Studio</h1>")


@app.get("/how-it-works", response_class=HTMLResponse)
async def how_it_works_page():
    """Render How It Works & AI Engine Architecture."""
    path = os.path.join("static", "how_it_works.html")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>How It Works</h1>")


# ==========================================
# REST API Routes
# ==========================================

@app.post("/api/analyze/email")
async def analyze_email_endpoint(payload: EmailScanRequest):
    """Analyze raw RFC 822 email: extracts headers, URLs, NLP body, and computes ML threat score."""
    raw_eml = payload.raw_eml.strip()
    if not raw_eml:
        raise HTTPException(status_code=400, detail="Empty email content received.")

    # 1. Multi-feature extraction
    extracted = extract_all_features_from_email(raw_eml)

    # 2. Machine Learning ensemble prediction & XAI attribution
    prediction = scoring_engine.predict_threat(extracted)

    # 3. Persistent History Record
    scan_rec = ScanDatabase.save_scan(
        scan_type="email",
        target_name=extracted.get("headers", {}).get("subject") or "Raw Email Inspection",
        prediction=prediction,
        extracted_features=extracted,
    )

    return {
        "scan_id": scan_rec["id"],
        "prediction": prediction,
        "features": extracted,
    }


@app.post("/api/analyze/upload")
async def analyze_upload_endpoint(file: UploadFile = File(...)):
    """Analyze uploaded .eml / .msg file."""
    content_bytes = await file.read()
    if len(content_bytes) > 500000:
        raise HTTPException(status_code=400, detail="Uploaded file exceeds 500KB maximum size limit.")
    raw_eml = content_bytes.decode("utf-8", errors="replace")
    
    extracted = extract_all_features_from_email(raw_eml)
    prediction = scoring_engine.predict_threat(extracted)

    scan_rec = ScanDatabase.save_scan(
        scan_type="email",
        target_name=file.filename or "Uploaded EML File",
        prediction=prediction,
        extracted_features=extracted,
    )

    return {
        "scan_id": scan_rec["id"],
        "filename": file.filename,
        "prediction": prediction,
        "features": extracted,
    }


@app.post("/api/analyze/url")
async def analyze_url_endpoint(payload: UrlScanRequest):
    """Fast lexical and heuristic analysis of a URL for Chrome Extension and Web Scanner."""
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="Empty URL provided.")

    # Scheme validation: reject javascript:, data:, file:, etc.
    _lower = url.lower().rstrip(":")
    _blocked_prefixes = ("javascript:", "data:", "file:", "vbscript:", "blob:")
    if any(_lower.startswith(bp) for bp in _blocked_prefixes):
        raise HTTPException(status_code=400, detail=f"Blocked scheme: URL must be http:// or https://.")

    analysis = UrlFeatureExtractor.analyze_single_url(url)
    risk = analysis.get("risk_score", 0.0)
    severity = "CRITICAL" if risk >= 70 else ("HIGH" if risk >= 40 else ("MEDIUM" if risk >= 25 else "LOW"))
    scan_rec = ScanDatabase.save_scan(
        scan_type="url",
        target_name=url[:80],
        prediction={
            "threat_score": risk,
            "severity": severity,
            "confidence_percentage": 92.0,
            "category": "MALICIOUS LINK" if risk >= 40 else "BENIGN LINK",
            "soc_action": "Block URL at edge proxy and DNS sinkhole" if risk >= 40 else "Permit URL traffic",
        },
        extracted_features={"url": analysis},
    )
    analysis["scan_id"] = scan_rec["id"]
    return analysis


@app.post("/api/analyze/text")
async def analyze_text_endpoint(payload: TextScanRequest):
    """Analyze SMS, BEC, or general text message for psychological coercion and scam markers."""
    text = payload.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Empty text provided.")

    nlp = NlpBodyExtractor.analyze_text_nlp(text)
    
    # Simple simulated email wrapper to compute overall ML prediction
    simulated_eml = f"""From: Unknown Sender <unknown@external-sms.net>
Subject: Urgent Security Notification
Content-Type: text/plain

{text}
"""
    extracted = extract_all_features_from_email(simulated_eml)
    prediction = scoring_engine.predict_threat(extracted)

    scan_rec = ScanDatabase.save_scan(
        scan_type="text",
        target_name=text[:60],
        prediction=prediction,
        extracted_features=extracted,
    )

    return {
        "scan_id": scan_rec["id"],
        "nlp": nlp,
        "prediction": prediction,
    }


@app.get("/api/history")
async def get_history_endpoint(limit: int = 25):
    """Retrieve recent scan triage records."""
    return ScanDatabase.get_recent_scans(limit=min(100, max(1, limit)))


@app.get("/api/history/{scan_id}")
async def get_history_detail_endpoint(scan_id: str):
    """Retrieve full details of a historical scan by ID."""
    rec = ScanDatabase.get_scan_by_id(scan_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return rec


@app.delete("/api/history/{scan_id}")
async def delete_history_endpoint(scan_id: str):
    """Delete a single scan history record."""
    deleted = ScanDatabase.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return {"status": "deleted", "id": scan_id}


@app.delete("/api/history")
async def clear_all_history_endpoint():
    """Clear all scan history records."""
    ScanDatabase.clear_all()
    return {"status": "cleared"}


@app.get("/api/model/metrics")
async def get_model_metrics_endpoint():
    """Retrieve ML and NLP performance metrics."""
    metrics_path = os.path.join("engine", "model_metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"status": "training_metrics_unavailable"}


@app.post("/api/analyze/sandbox")
async def analyze_sandbox_endpoint(payload: SandboxRequest):
    """Generate safe virtual DOM preview and harvesting telemetry for destination URL."""
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="Empty URL provided.")

    preview = SandboxAnalyzer.generate_sandbox_preview(url)
    return preview


@app.post("/api/check-disposable")
async def check_disposable_endpoint(payload: DisposableCheckRequest):
    """Evaluate whether an email address or domain is a throwaway burner or disposable provider."""
    result = DisposableEmailChecker.check(payload.email_or_domain)
    return result


@app.get("/api/threat-profile")
async def get_threat_profile_endpoint():
    """Retrieve active defense contractor threat profile and custom rules."""
    return CustomProfileManager.get_active_profile()


@app.post("/api/threat-profile")
async def update_threat_profile_endpoint(payload: ThreatProfileModel):
    """Save updated threat profile, monitored brands, and detection thresholds."""
    saved = CustomProfileManager.save_profile(payload.dict())
    return {"status": "success", "profile": saved}


@app.post("/api/custom-scenario/generate")
async def generate_custom_scenario_endpoint(payload: CustomScenarioRequest):
    """Dynamically generate a personalized spear-phishing situation tailored to target defense contractor parameters."""
    scenario = CustomProfileManager.generate_personalized_scenario(payload)
    return scenario


@app.get("/api/scenarios")
async def get_scenarios_endpoint():
    """Retrieve list of preloaded defense contractor phishing scenarios and legitimate emails."""
    return get_all_scenarios()


@app.get("/api/scenarios/{scenario_id}")
async def get_scenario_endpoint(scenario_id: str):
    """Retrieve full scenario data including raw RFC 822 EML."""
    return get_scenario_by_id(scenario_id)


@app.get("/api/export/incident/{scenario_id}")
async def export_incident_endpoint(scenario_id: str):
    """Generate formal Defense Contractor SOC Incident Response Ticket with full IOCs."""
    scenario = get_scenario_by_id(scenario_id)
    raw_eml = scenario.get("raw_eml", "")
    
    extracted = extract_all_features_from_email(raw_eml)
    pred = scoring_engine.predict_threat(extracted)

    headers = extracted.get("headers", {})
    urls = extracted.get("urls", {}).get("urls", [])

    ioc_domains = [headers.get("from_domain", "")]
    if headers.get("return_path_domain"):
        ioc_domains.append(headers.get("return_path_domain"))
    for u in urls:
        ioc_domains.append(u.get("hostname", ""))
    ioc_domains = list(set([d for d in ioc_domains if d]))

    ioc_ips = []
    if headers.get("spf", {}).get("client_ip"):
        ioc_ips.append(headers.get("spf", {}).get("client_ip"))
    if headers.get("relay", {}).get("originating_ip"):
        ioc_ips.append(headers.get("relay", {}).get("originating_ip"))
    for u in urls:
        if u.get("is_ip_address"):
            ioc_ips.append(u.get("hostname"))
    ioc_ips = list(set([ip for ip in ioc_ips if ip]))

    markdown_ticket = f"""# DEFENSE CONTRACTOR SOC INCIDENT RESPONSE TICKET
**Incident ID**: INC-{scenario_id.upper()[:12]}-2026
**Classification**: CUI / DEFENSE CONTRACTOR PROPRIETARY
**Severity Level**: {pred.get('severity')} ({pred.get('threat_score')}% Threat Probability)
**Threat Vector**: {pred.get('category')}
**Date/Time**: 2026-09-14 13:20:00 UTC
**Investigating System**: Trac-I Defense AI Engine v1.0.0

---

## 1. Executive Incident Summary
{scenario.get('summary')}

- **Recipient Target**: {scenario.get('target', 'Enterprise Personnel')}
- **Sender Disguise**: {headers.get('from')}
- **Return-Path**: {headers.get('return_path')}
- **Subject**: {headers.get('subject')}
- **SOC Action**: {pred.get('soc_action')}

---

## 2. Key Threat Indicators & Evidence
- **SPF Status**: {headers.get('spf', {}).get('status', 'none').upper()}
- **DKIM Status**: {headers.get('dkim', {}).get('status', 'none').upper()}
- **DMARC Status**: {headers.get('dmarc', {}).get('status', 'none').upper()}
- **Sender Alignment**: Return-Path Mismatch = {headers.get('mismatches', {}).get('return_path')}, Reply-To Mismatch = {headers.get('mismatches', {}).get('reply_to')}
- **Homoglyph Exploits**: {'Detected in embedded hyperlinks' if extracted.get('urls', {}).get('any_homoglyph') else 'None'}
- **Psychological Triggers**: Urgency ({extracted.get('nlp', {}).get('counts', {}).get('urgency')}), Fear ({extracted.get('nlp', {}).get('counts', {}).get('fear')}), Credential Solicitation ({extracted.get('nlp', {}).get('has_credential_solicitation')})

---

## 3. Indicators of Compromise (IOCs)
### Malicious / Suspect Domains:
{chr(10).join([f"- `{d}`" for d in ioc_domains]) if ioc_domains else "- None"}

### Source IPs & Rogue Relays:
{chr(10).join([f"- `{ip}`" for ip in ioc_ips]) if ioc_ips else "- None"}

### Malicious URLs:
{chr(10).join([f"- `{u.get('url')}` (Risk Score: {u.get('risk_score')}%)" for u in urls]) if urls else "- None"}

---

## 4. Recommended Containment & Remediation Actions
1. **Firewall / Proxy**: Immediately block all outbound connections to the identified IOC domains and IPs.
2. **Mail Gateway (SEG)**: Purge message ID `{headers.get('message_id')}` from all recipient mailboxes across the tenant.
3. **Identity & Access Management (IAM)**: Force password reset and revoke active OAuth/SAML refresh tokens for any users who clicked embedded links.
4. **Endpoint Security (EDR)**: Inspect endpoint cache for cached DNS queries to identified homoglyphs.
"""

    return {
        "incident_id": f"INC-{scenario_id.upper()[:12]}-2026",
        "severity": pred.get("severity"),
        "threat_score": pred.get("threat_score"),
        "category": pred.get("category"),
        "soc_action": pred.get("soc_action"),
        "ioc_domains": ioc_domains,
        "ioc_ips": ioc_ips,
        "ioc_urls": [u.get("url") for u in urls],
        "markdown_ticket": markdown_ticket,
    }


@app.get("/api/download/extension")
async def download_extension_endpoint():
    """Download the packaged Chrome Extension zip file."""
    zip_path = os.path.join("static", "downloads", "trac-i-extension.zip")
    if not os.path.exists(zip_path):
        # Package on the fly if needed
        from scripts.package_extension import package_extension
        package_extension()

    return FileResponse(
        zip_path,
        media_type="application/zip",
        filename="trac-i-extension.zip",
    )
