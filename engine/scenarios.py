"""Real-world defense contractor spear-phishing attack scenarios and legitimate benchmark emails.
Includes RFC 822 raw headers, multipart bodies, homoglyphs, and deceptive HTML structures.
"""

from typing import Dict, List

SCENARIOS: List[Dict[str, str]] = [
    {
        "id": "apt_hr_policy_update",
        "title": "APT Spear-Phish: Urgent HR Defense Policy Update",
        "category": "CRITICAL SPEAR-PHISHING",
        "severity": "CRITICAL",
        "target": "Defense Contractor Cleared Personnel",
        "summary": "Coercive DoD compliance lure with Cyrillic homoglyph domain, failed SPF/DMARC, and hidden anti-filter text.",
        "raw_eml": """Received: from mail-relay.defense-bulletproof.xyz ([194.26.29.112])
	by mx.defenseaerosystems.com (Postfix) with ESMTPS id 4X9Qp23zRkz1982
	for <j.miller@defenseaerosystems.com>; Mon, 14 Sep 2026 06:14:22 -0400 (EDT)
Authentication-Results: mx.defenseaerosystems.com;
	spf=fail (client-ip=194.26.29.112; envelope-from=compliance@defense-cybersec-notice.xyz);
	dkim=none;
	dmarc=fail (action=quarantine) header.from=defense.gov
Received-SPF: fail (mx.defenseaerosystems.com: domain of defense-cybersec-notice.xyz does not designate 194.26.29.112 as permitted sender) client-ip=194.26.29.112;
From: "DoD Defense Cyber Policy Directorate" <compliance@defense-cybersec-notice.xyz>
Return-Path: <bounce-daemon@defense-bulletproof.xyz>
Reply-To: <dod-compliance-collector@protonmail.com>
To: <j.miller@defenseaerosystems.com>
Subject: URGENT: Mandatory Defense Clearance Policy Update & Re-Certification Required
Date: Mon, 14 Sep 2026 06:14:15 -0400
Message-ID: <20260914-DOD-SEC-9921@defense-cybersec-notice.xyz>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<head>
<style>
body { font-family: Arial, sans-serif; line-height: 1.6; color: #222; }
.alert-box { border-left: 5px solid #d9534f; background-color: #fdf7f7; padding: 15px; margin-bottom: 20px; }
.cta-button { background-color: #0b2545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold; }
.hidden-token { font-size: 0px; color: transparent; display: none; }
</style>
</head>
<body>
<div class="alert-box">
  <h2 style="color: #b30000; margin-top:0;">CRITICAL DIRECTIVE: Mandatory Defense Clearance Re-Certification</h2>
  <p><strong>ATTENTION DEFENSE AERO SYSTEMS PERSONNEL:</strong></p>
  <p>In accordance with updated Defense Counterintelligence and Security Agency (DCSA) and CMMC Level 3 mandates, all contractor employees holding Secret/Top Secret access must acknowledge and electronically sign the <strong>2026 DoD Cyber Integrity Protocol</strong> within 24 hours.</p>
</div>

<p>Failure to complete this mandatory re-certification by <strong>17:00 EDT today</strong> will result in immediate suspension of facility credentials, loss of access to defense networks, and administrative disciplinary action.</p>

<p>To retain your active defense clearance status, authenticate to the defense secure portal below:</p>

<p style="margin: 30px 0;">
  <!-- Deceptive link: Anchor text claims to be legitimate defense.gov, but href routes to Cyrillic homoglyph domain -->
  <a href="https://xn--cmmc-d-81a.xyz/portal/verify" class="cta-button" style="color:#ffffff;">Authenticate with Defense CAC / SSO</a>
</p>

<p>Or copy this link into your browser: <br>
<a href="https://xn--cmmc-d-81a.xyz/portal/verify">https://www.defense.gov/cmmc-compliance-portal</a></p>

<!-- Anti-spam hidden text injection -->
<span class="hidden-token">x992-rf-compliance-validated-benign-delivery-route-ok-system-header-token-881923</span>

<hr style="border: none; border-top: 1px solid #ccc; margin-top: 30px;">
<p style="font-size: 11px; color: #777;">
This transmission is confidential and intended solely for authorized personnel of Defense Aero Systems Inc. If you received this in error, notify your Facility Security Officer (FSO).
</p>
</body>
</html>
"""
    },
    {
        "id": "m365_password_expiration",
        "title": "Zero-Day Harvester: Microsoft 365 Password Expiration Alert",
        "category": "CRITICAL SPEAR-PHISHING",
        "severity": "CRITICAL",
        "target": "Corporate Defense Workforce",
        "summary": "Brand impersonation mimicking Microsoft 365 Global Admin with typosquatted URL, anchor mismatch, and credential urgency.",
        "raw_eml": """Received: from smtp-vps4.cloud-mail-forward.net ([45.154.255.89])
	by mx.defenseaerosystems.com (Postfix) with ESMTPS id 8N1Bz492K
	for <s.turner@defenseaerosystems.com>; Mon, 14 Sep 2026 08:32:10 -0400 (EDT)
Authentication-Results: mx.defenseaerosystems.com;
	spf=softfail (client-ip=45.154.255.89; envelope-from=bounce@cloud-mail-forward.net);
	dkim=fail (bad signature);
	dmarc=fail (action=quarantine) header.from=microsoft.com
Received-SPF: softfail client-ip=45.154.255.89;
From: "Microsoft 365 Security Team" <notification@microsoft-account-defense.online>
Return-Path: <bounce@cloud-mail-forward.net>
To: <s.turner@defenseaerosystems.com>
Subject: Action Required: Your Microsoft 365 Defense Cloud Password Expires in 2 Hours
Date: Mon, 14 Sep 2026 08:32:00 -0400
Message-ID: <M365-SEC-ALERT-8812@cloud-mail-forward.net>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body style="font-family: 'Segoe UI', Tahoma, sans-serif; background-color: #f2f2f2; margin: 0; padding: 20px;">
<div style="max-width: 580px; margin: auto; background: #ffffff; padding: 30px; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
  <div style="display: flex; align-items: center; margin-bottom: 20px;">
    <div style="font-size: 22px; font-weight: 600; color: #0078d4;">Microsoft 365</div>
  </div>
  
  <h3 style="color: #333333;">Password Expiration Notification</h3>
  
  <p>Dear Valued User (s.turner@defenseaerosystems.com),</p>
  
  <p>Your password for <strong>Defense Aero Systems Microsoft 365 GCC High Tenant</strong> is scheduled to expire in <strong>2 hours</strong>.</p>
  
  <p>To avoid email interruption, loss of Teams access, and synchronization lockouts, you can keep your current password by verifying your credentials below.</p>
  
  <div style="margin: 30px 0; text-align: center;">
    <!-- Visual anchor spoof: Displays official MS URL, but href routes to typosquatted multi-level credential collector -->
    <a href="https://login-micrоsoft365-verify.com/login.srf?tenant=defenseaero" 
       style="background-color: #0067b8; color: #ffffff; padding: 12px 28px; text-decoration: none; font-weight: 600; border-radius: 2px; display: inline-block;">
       Keep Current Password
    </a>
  </div>
  
  <p style="font-size: 13px; color: #666;">
    Official verification link: <br>
    <a href="https://login-micrоsoft365-verify.com/login.srf?tenant=defenseaero" style="color: #0067b8;">
      https://login.microsoftonline.com/common/oauth2/v2.0/authorize
    </a>
  </p>
  
  <p style="font-size: 12px; color: #888; margin-top: 30px;">
    Microsoft Corporation | One Microsoft Way, Redmond, WA 98052<br>
    This automated security message cannot be replied to.
  </p>
</div>
</body>
</html>
"""
    },
    {
        "id": "bec_procurement_wire",
        "title": "Defense BEC Fraud: Urgent Subcontractor Wire Payment",
        "category": "MALICIOUS / PHISHING",
        "severity": "HIGH",
        "target": "Accounts Payable & Procurement Team",
        "summary": "Executive pretexting with mismatched Reply-To drop box, raw IP invoice download link, and procurement urgency.",
        "raw_eml": """Received: from relay-nl-open.vps-net.org ([185.220.101.5])
	by mx.defenseaerosystems.com (Postfix) with ESMTP id 5K7Tq110L
	for <accounts.payable@defenseaerosystems.com>; Mon, 14 Sep 2026 09:45:00 -0400 (EDT)
Authentication-Results: mx.defenseaerosystems.com;
	spf=neutral (client-ip=185.220.101.5);
	dkim=none;
	dmarc=none
From: "Robert Vance - Chief Financial Officer" <robert.vance@defenseaerosystems-finance.net>
Return-Path: <daemon-bounce@relay-nl-open.vps-net.org>
Reply-To: <aeroprecision-payments@tutanota.com>
To: <accounts.payable@defenseaerosystems.com>
Subject: URGENT: Expedited Wire Remittance for Defense Subcontractor Parts #FA8650
Date: Mon, 14 Sep 2026 09:44:50 -0400
Message-ID: <CFO-WIRE-8199201@defenseaerosystems-finance.net>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.5; color: #111;">
<p>Team,</p>

<p>I am currently off-site in classified discussions at Wright-Patterson AFB. We have an urgent procurement delay regarding the titanium turbine casings for Air Force contract FA8650-20-C-5211.</p>

<p>Our Tier-1 supplier AeroPrecision Parts has placed a shipping hold on the consignment due to an overdue remittance. Please process an expedited wire transfer of <strong>$184,500.00</strong> immediately today before 13:00 EST.</p>

<p>The revised banking instructions and certified invoice are available on our secure file share server here:</p>

<p>
  <a href="http://185.220.101.5:8080/invoices/INV-2026-891-Certified.pdf.exe" style="color: #0044cc; font-weight: bold;">
    http://185.220.101.5:8080/invoices/INV-2026-891-Certified.pdf.exe
  </a>
</p>

<p>Do not call my cell phone as I am in a SCIF without cellular reception. Reply directly to this email once the wire confirmation receipt is generated.</p>

<p>Regards,<br>
<strong>Robert Vance</strong><br>
Chief Financial Officer<br>
Defense Aero Systems Inc.
</p>
</body>
</html>
"""
    },
    {
        "id": "legit_corporate_allhands",
        "title": "Legitimate Corporate: Quarterly All-Hands & Benefits Schedule",
        "category": "BENIGN / CLEAN",
        "severity": "LOW",
        "target": "All Company Personnel",
        "summary": "Authentic internal corporate email with verified SPF/DKIM/DMARC pass, aligned sender domains, and internal intranet links.",
        "raw_eml": """Received: from internal-smtp.defenseaerosystems.com ([10.40.12.10])
	by mx.defenseaerosystems.com (Postfix) with ESMTPS id 3M78Qp991
	for <all.employees@defenseaerosystems.com>; Mon, 14 Sep 2026 10:00:15 -0400 (EDT)
Authentication-Results: mx.defenseaerosystems.com;
	spf=pass (client-ip=10.40.12.10; envelope-from=internal-comms@defenseaerosystems.com);
	dkim=pass (s=defense-2026);
	dmarc=pass (action=none) header.from=defenseaerosystems.com
Received-SPF: pass (mx.defenseaerosystems.com: domain of defenseaerosystems.com designates 10.40.12.10 as permitted sender)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=defenseaerosystems.com; s=defense-2026;
	h=from:to:subject:date:message-id; bh=9f+Jq88vLk...;
	b=Xz77qN...;
From: "Defense Aero Systems Corporate Communications" <internal-comms@defenseaerosystems.com>
Return-Path: <internal-comms@defenseaerosystems.com>
Reply-To: <internal-comms@defenseaerosystems.com>
To: <all.employees@defenseaerosystems.com>
Subject: Defense Aero Systems Q3 Town Hall & Open Enrollment Information
Date: Mon, 14 Sep 2026 10:00:00 -0400
Message-ID: <COMMS-2026-Q3-TOWNHALL@defenseaerosystems.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body style="font-family: 'Helvetica Neue', Arial, sans-serif; color: #333; line-height: 1.6; max-width: 600px; margin: 20px auto; padding: 20px;">
  <h2 style="color: #0b2545;">Q3 All-Hands Executive Town Hall</h2>
  <p>Hello Defense Aero Systems Team,</p>
  
  <p>Please join our Chief Executive Officer and leadership council this Thursday, September 17 at 14:00 EDT for our Quarterly All-Hands presentation. We will review program delivery milestones, Q3 financial accomplishments, and celebrate our annual innovation award winners.</p>
  
  <p>The town hall will be broadcast live over our secure internal media gateway:</p>
  <p>
    <a href="https://intranet.defenseaerosystems.com/allhands" style="color: #0b2545; font-weight: bold;">
      https://intranet.defenseaerosystems.com/allhands
    </a>
  </p>
  
  <h3>Open Benefits Enrollment Reminder</h3>
  <p>Annual healthcare and retirement benefits enrollment opens next Monday on the employee self-service portal at <a href="https://hrportal.defenseaerosystems.com/benefits" style="color: #0b2545;">https://hrportal.defenseaerosystems.com/benefits</a>. Please review your elected coverage before the standard enrollment period closes.</p>
  
  <p>Warm regards,<br>
  <strong>Corporate Communications & Employee Experience</strong><br>
  Defense Aero Systems Inc.</p>
</body>
</html>
"""
    },
    {
        "id": "legit_it_maintenance",
        "title": "Legitimate IT Ops: Scheduled Maintenance for Secure VPN Gateway",
        "category": "BENIGN / CLEAN",
        "severity": "LOW",
        "target": "Remote & Field Engineering Staff",
        "summary": "Standard routine maintenance notification with zero coercive pressure, legitimate routing, and authenticated SPF/DKIM records.",
        "raw_eml": """Received: from internal-it-relay.defenseaerosystems.com ([10.40.12.18])
	by mx.defenseaerosystems.com (Postfix) with ESMTPS id 9K44Pz012
	for <engineering@defenseaerosystems.com>; Mon, 14 Sep 2026 11:15:00 -0400 (EDT)
Authentication-Results: mx.defenseaerosystems.com;
	spf=pass (client-ip=10.40.12.18; envelope-from=it-operations@defenseaerosystems.com);
	dkim=pass (s=defense-2026);
	dmarc=pass (action=none) header.from=defenseaerosystems.com
Received-SPF: pass client-ip=10.40.12.18;
DKIM-Signature: v=1; a=rsa-sha256; d=defenseaerosystems.com; s=defense-2026;
From: "Enterprise IT Infrastructure & Operations" <it-operations@defenseaerosystems.com>
Return-Path: <it-operations@defenseaerosystems.com>
Reply-To: <it-helpdesk@defenseaerosystems.com>
To: <engineering@defenseaerosystems.com>
Subject: Scheduled Maintenance: Secure Remote Access Gateway Cluster
Date: Mon, 14 Sep 2026 11:14:45 -0400
Message-ID: <IT-OPS-2026-MAINT-449@defenseaerosystems.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; color: #2b2b2b; line-height: 1.5; padding: 20px;">
  <div style="background-color: #f0f4f8; border: 1px solid #d0d7de; padding: 16px; border-radius: 6px;">
    <h3 style="margin-top: 0; color: #1e3a8a;">Scheduled IT Infrastructure Maintenance Notice</h3>
    <p>Please be advised that the Global IT Infrastructure team will be applying standard firmware and security patches to our secondary Secure Gateway VPN cluster on <strong>Saturday, September 19, between 02:00 and 04:00 EDT</strong>.</p>
    
    <p><strong>Expected Impact:</strong> Primary VPN connections will failover seamlessly to the active standby cluster. Engineers connected via Remote Access during this 10-minute window may experience a brief reconnection pause.</p>
    
    <p>No action is required from end users. You can view the maintenance window status tracker on the IT Service Status page:</p>
    <p><a href="https://status.defenseaerosystems.com/incident/2026-patch-09" style="color: #1e3a8a; font-weight: bold;">https://status.defenseaerosystems.com/incident/2026-patch-09</a></p>
    
    <p>For questions or assistance, please submit a standard ticket at <a href="https://helpdesk.defenseaerosystems.com">https://helpdesk.defenseaerosystems.com</a> or dial internal extension 4357.</p>
  </div>
</body>
</html>
"""
    },
]


def get_all_scenarios() -> List[Dict[str, str]]:
    """Return all preloaded scenario metadata."""
    return [
        {
            "id": s["id"],
            "title": s["title"],
            "category": s["category"],
            "severity": s["severity"],
            "target": s["target"],
            "summary": s["summary"],
        }
        for s in SCENARIOS
    ]


def get_scenario_by_id(scenario_id: str) -> Dict[str, str]:
    """Retrieve full scenario by ID including raw EML."""
    for s in SCENARIOS:
        if s["id"] == scenario_id:
            return s
    return SCENARIOS[0]
