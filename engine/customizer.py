"""Custom Threat Profile & Defense Scenario Personalization Engine.

Allows defense contractors, critical infrastructure operators, and enterprises
to configure tailored threat profiles, custom brand watchlists, executive impersonation targets,
detection sensitivity thresholds, and dynamically simulate spear-phishing situations.
"""

from typing import Any, Dict, List, Optional
import json
import os
import re
from pydantic import BaseModel

# Default Defense Contractor Threat Profile
DEFAULT_DEFENSE_PROFILE: Dict[str, Any] = {
    "profile_id": "defense_contractor_gcc_high",
    "organization_name": "Defense Aero Systems Inc.",
    "organization_sector": "Critical National Infrastructure (Defense & Aerospace)",
    "protected_domains": [
        "defenseaerosystems.com",
        "intranet.defenseaerosystems.com",
        "hrportal.defenseaerosystems.com",
        "vpn.defenseaerosystems.com",
    ],
    "monitored_brands": [
        "Microsoft 365 GCC High",
        "DoD Defense Cyber Directorate",
        "DCSA Clearance Portal",
        "CMMC Compliance Gateway",
        "Okta Defense SSO",
        "Duo Federal MFA",
    ],
    "executive_watchlist": [
        {"name": "Robert Vance", "title": "Chief Financial Officer", "email": "robert.vance@defenseaerosystems.com"},
        {"name": "Col. Marcus Reed", "title": "Director of Facility Security (FSO)", "email": "m.reed@defenseaerosystems.com"},
        {"name": "Elena Rostova", "title": "VP of Human Resources", "email": "e.rostova@defenseaerosystems.com"},
        {"name": "David Sterling", "title": "Chief Information Security Officer (CISO)", "email": "d.sterling@defenseaerosystems.com"},
    ],
    "target_roles": [
        "Cleared Personnel (Secret / Top Secret / SCI)",
        "Avionics & Embedded Software Engineers",
        "Procurement & Subcontractor Payables",
        "Executive Leadership & Program Managers",
    ],
    "sensitivity_settings": {
        "homoglyph_strictness": 95,           # 0-100 (Alert on single confusable character)
        "dmarc_enforcement_level": "strict",   # "strict" (reject on softfail/fail) | "balanced"
        "urgency_coercion_weight": 1.4,       # Multiplier on NLP urgency score
        "disposable_email_action": "quarantine", # "quarantine" | "block" | "flag"
        "zero_day_domain_lag_defense": True,  # Heuristics bypass static reputation cache
    }
}


class ThreatProfileModel(BaseModel):
    organization_name: str
    organization_sector: str
    protected_domains: List[str]
    monitored_brands: List[str]
    executive_watchlist: List[Dict[str, str]]
    target_roles: List[str]
    sensitivity_settings: Dict[str, Any]


class CustomScenarioRequest(BaseModel):
    lure_type: str                  # "hr_policy_update" | "m365_password_expiry" | "procurement_wire" | "custom"
    target_employee_name: str       # e.g. "Dr. Sarah Jenkins"
    target_employee_role: str       # e.g. "Senior Defense Cleared Propulsion Engineer"
    target_employee_email: str      # e.g. "s.jenkins@defenseaerosystems.com"
    attacker_technique: str         # "cyrillic_homoglyph" | "anchor_mismatch" | "zero_font_hidden" | "disposable_relay" | "all_techniques"
    custom_subject: Optional[str] = None
    urgency_deadline: Optional[str] = "2 hours"


class CustomProfileManager:
    """Manages custom security profiles and dynamic spear-phish situation synthesis."""

    _PROFILE_FILE = "engine/active_threat_profile.json"

    @classmethod
    def get_active_profile(cls) -> Dict[str, Any]:
        """Load currently saved profile or default."""
        if os.path.exists(cls._PROFILE_FILE):
            try:
                with open(cls._PROFILE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return DEFAULT_DEFENSE_PROFILE

    @classmethod
    def save_profile(cls, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Persist customized profile settings."""
        os.makedirs(os.path.dirname(cls._PROFILE_FILE), exist_ok=True)
        with open(cls._PROFILE_FILE, "w", encoding="utf-8") as f:
            json.dump(profile_data, f, indent=2)
        return profile_data

    @classmethod
    def generate_personalized_scenario(cls, req: CustomScenarioRequest) -> Dict[str, Any]:
        """Synthesize an authentic spear-phishing situation customized to user specifications."""
        profile = cls.get_active_profile()
        org = profile.get("organization_name", "Defense Aero Systems Inc.")
        domain = profile.get("protected_domains", ["defenseaerosystems.com"])[0]
        emp_name = req.target_employee_name or "Valued Cleared Personnel"
        emp_email = req.target_employee_email or f"personnel@{domain}"
        emp_role = req.target_employee_role or "Cleared Systems Specialist"
        deadline = req.urgency_deadline or "24 hours"

        # 1. Situation: Urgent HR Policy Update
        if req.lure_type in ["hr_policy_update", "urgent_hr_policy"]:
            subject = req.custom_subject or f"MANDATORY: Urgent {org} Security & Clearance Policy Compliance Acknowledgment"
            from_display = "HR & Defense Security Compliance Directorate"
            from_addr = "compliance@dcsa-policy-compliance.xyz"
            homoglyph_domain = "xn--cmmc-d-81a.xyz"
            
            raw_eml = f"""Received: from mail-relay.defense-bulletproof.xyz ([194.26.29.112])
	by mx.{domain} (Postfix) with ESMTPS id 9F84Q10219
	for <{emp_email}>; Mon, 14 Sep 2026 09:12:00 -0400 (EDT)
Authentication-Results: mx.{domain};
	spf=fail (client-ip=194.26.29.112; envelope-from=compliance@dcsa-policy-compliance.xyz);
	dkim=fail;
	dmarc=fail (action=quarantine) header.from=defense.gov
Received-SPF: fail client-ip=194.26.29.112;
From: "{from_display}" <{from_addr}>
Return-Path: <bounce-daemon@defense-bulletproof.xyz>
Reply-To: <dcsa-compliance-inbox@mailinator.com>
To: "{emp_name}" <{emp_email}>
Subject: {subject}
Date: Mon, 14 Sep 2026 09:11:50 -0400
Message-ID: <HR-COMPLIANCE-2026-ALERT-9912@{from_addr.split('@')[-1]}>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 8bit

<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; color: #1e293b; line-height: 1.6; padding: 20px;">
  <div style="background: #fff; border: 1px solid #cbd5e1; border-top: 4px solid #b91c1c; padding: 24px; border-radius: 6px; max-width: 620px; margin: 0 auto;">
    <h2 style="color: #b91c1c; margin-top: 0;">CRITICAL DIRECTIVE: {org}</h2>
    <p><strong>Employee:</strong> {emp_name} ({emp_role})</p>
    
    <p>In accordance with updated Defense Counterintelligence and Security Agency (DCSA) directives and CMMC 2.0 regulations, all defense contractor personnel must review and sign the revised <strong>Defense Clearance Safeguarding Standard</strong> within <strong>{deadline}</strong>.</p>
    
    <div style="background: #fef2f2; border-left: 4px solid #ef4444; padding: 12px; margin: 16px 0; font-size: 13px; color: #991b1b;">
      <strong>MANDATORY NOTICE:</strong> Failure to submit your signed acknowledgment by the required deadline will result in immediate suspension of facility access, revocation of active DoD security tokens, and formal disciplinary review.
    </div>

    <p style="text-align: center; margin: 26px 0;">
      <a href="https://{homoglyph_domain}/portal/auth?user={emp_email}" 
         style="background-color: #0b2545; color: #ffffff; padding: 12px 24px; text-decoration: none; font-weight: bold; border-radius: 4px; display: inline-block;">
         Authenticate with Defense CAC / SSO
      </a>
    </p>

    <p style="font-size: 12px; color: #64748b;">
      Official Defense Compliance URL: <br>
      <a href="https://{homoglyph_domain}/portal/auth?user={emp_email}">https://www.defense.gov/cmmc-cleared-portal</a>
    </p>

    <!-- Hidden anti-spam token -->
    <span style="font-size: 0px; color: transparent; display: none;">x99-cleared-token-defense-internal-route-verified</span>
  </div>
</body>
</html>
"""
            technique_tags = ["Cyrillic IDN Homoglyph", "Urgency Coercion (Clearance Suspension)", "Mismatched Return-Path", "Burner Mailinator Drop-Box", "Zero-Font Hidden Padding"]

        # 2. Situation: Microsoft 365 Password Expiration Notice
        elif req.lure_type in ["m365_password_expiry", "m365_password", "password_expiration"]:
            subject = req.custom_subject or f"ACTION REQUIRED: Your {org} Microsoft 365 GCC High Password Expires in {deadline}"
            from_display = f"{org} IT Helpdesk & Microsoft 365 Admin"
            from_addr = f"admin@m365-tenant-{domain.split('.')[0]}.online"
            typosquat_url = "https://login-micrоsoft365-verify.com/login.srf" # Contains Cyrillic 'о'
            
            raw_eml = f"""Received: from vps-rel-eu.cloudhost-node.net ([45.154.255.89])
	by mx.{domain} (Postfix) with ESMTPS id 3L11K8900
	for <{emp_email}>; Mon, 14 Sep 2026 08:30:15 -0400 (EDT)
Authentication-Results: mx.{domain};
	spf=fail (client-ip=45.154.255.89; envelope-from=bounce@cloudhost-node.net);
	dkim=fail;
	dmarc=fail (action=quarantine) header.from=microsoft.com
Received-SPF: fail client-ip=45.154.255.89;
From: "{from_display}" <{from_addr}>
Return-Path: <bounce@cloudhost-node.net>
Reply-To: <m365-support@throwaway-inbox.cc>
To: "{emp_name}" <{emp_email}>
Subject: {subject}
Date: Mon, 14 Sep 2026 08:30:00 -0400
Message-ID: <M365-PASS-EXPIRY-99128@{from_addr.split('@')[-1]}>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 8bit

<!DOCTYPE html>
<html>
<body style="font-family: 'Segoe UI', Tahoma, sans-serif; background: #f3f4f6; padding: 20px;">
  <div style="max-width: 560px; margin: 0 auto; background: #ffffff; padding: 30px; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
    <div style="font-size: 22px; font-weight: bold; color: #0078d4; margin-bottom: 16px;">Microsoft 365</div>
    
    <h3 style="color: #1f2937; margin-bottom: 8px;">MANDATORY: Your password will expire within {deadline}</h3>
    <p style="color: #4b5563; font-size: 14px;">Hello {emp_name},</p>
    
    <p style="color: #4b5563; font-size: 14px;">
      The password for your account <strong>{emp_email}</strong> on tenant <strong>{org} GCC High</strong> is set to expire today. 
      Immediate action is required to prevent disruption to your Outlook, Teams, and secure defense repositories. Keep your current password by verifying your credentials below.
    </p>

    <div style="background: #fef2f2; border-left: 4px solid #ef4444; padding: 12px; margin: 16px 0; font-size: 13px; color: #991b1b;">
      <strong>URGENT NOTICE:</strong> Failure to renew credentials within {deadline} will lead to immediate account suspension and revocation of active DoD security tokens.
    </div>

    <div style="text-align: center; margin: 28px 0;">
      <a href="{typosquat_url}?tenant={domain}&user={emp_email}" 
         style="background: #0067b8; color: #ffffff; padding: 12px 28px; text-decoration: none; font-weight: bold; border-radius: 2px; display: inline-block;">
        Keep Current Password & Authenticate
      </a>
    </div>

    <p style="font-size: 12px; color: #6b7280;">
      Or visit your official defense tenant login: <br>
      <a href="{typosquat_url}?tenant={domain}&user={emp_email}" style="color: #0067b8;">
        https://login.microsoftonline.com/common/oauth2/v2.0/authorize
      </a>
    </p>

    <span style="font-size: 0px; color: transparent; display: none;">x-defense-token-m365-bypass-padding</span>

    <p style="font-size: 11px; color: #9ca3af; margin-top: 24px; border-top: 1px solid #e5e7eb; padding-top: 12px;">
      Microsoft Corporation &bull; One Microsoft Way, Redmond, WA &bull; Automated Defense Security Dispatch
    </p>
  </div>
</body>
</html>
"""
            technique_tags = ["Cyrillic Homoglyph ('о' in micrоsoft365)", "Anchor Mismatch (displays microsoftonline.com)", "Credential Harvesting Lure", "High-Pressure Expiry (2 Hours)", "Display Name IT Spoofing", "Zero-Font Hidden Padding"]

        # 3. Situation: Defense Subcontractor Wire Lure (BEC)
        else:
            cfo_name = profile.get("executive_watchlist", [{}])[0].get("name", "Robert Vance")
            subject = req.custom_subject or f"URGENT: Expedited Defense Subcontractor Parts Wire #{deadline}"
            from_display = f"{cfo_name} - {org} CFO"
            from_addr = f"robert.vance@{domain.split('.')[0]}-executive-dispatch.net"
            
            raw_eml = f"""Received: from relay-nl.vps-bulletproof.org ([185.220.101.5])
	by mx.{domain} (Postfix) with ESMTP id 7B90K23
	for <{emp_email}>; Mon, 14 Sep 2026 10:15:00 -0400 (EDT)
Authentication-Results: mx.{domain};
	spf=fail (client-ip=185.220.101.5);
	dkim=none;
	dmarc=fail (action=quarantine)
From: "{from_display}" <{from_addr}>
Return-Path: <daemon-bounce@relay-nl.vps-bulletproof.org>
Reply-To: <aeroprecision-payments@tutanota.com>
To: "{emp_name}" <{emp_email}>
Subject: {subject}
Date: Mon, 14 Sep 2026 10:14:40 -0400
Message-ID: <CFO-URGENT-WIRE-9921@{from_addr.split('@')[-1]}>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; color: #111; line-height: 1.5; padding: 20px;">
  <p>{emp_name},</p>
  <p>I am currently off-site in classified discussions at the Pentagon. We have an urgent shipment hold on critical titanium casing assemblies for our defense contract.</p>
  <p>Please process an immediate wire remittance of <strong>$148,250.00</strong> to our verified Tier-1 subcontractor within <strong>{deadline}</strong>.</p>
  <p>Download the certified remittance invoice and updated routing slip from our secure host:</p>
  <p><a href="http://185.220.101.5:8080/invoices/INV-2026-Certified.pdf.exe" style="color: #0044cc; font-weight: bold;">http://185.220.101.5:8080/invoices/INV-2026-Certified.pdf.exe</a></p>
  <p>Do not call as I am inside a SCIF without cell reception. Reply directly to this email with the wire confirmation number.</p>
  <p>Regards,<br><strong>{cfo_name}</strong><br>Chief Financial Officer<br>{org}</p>
</body>
</html>
"""
            technique_tags = ["Executive Pretexting (CFO Impersonation)", "Mismatched Reply-To Drop-Box", "Raw IP Executable Link (.pdf.exe)", "BEC Wire Fraud Pressure"]

        return {
            "title": f"Custom Situation: {subject}",
            "lure_type": req.lure_type,
            "target_employee": f"{emp_name} ({emp_role})",
            "organization": org,
            "subject": subject,
            "raw_eml": raw_eml,
            "technique_tags": technique_tags,
        }
