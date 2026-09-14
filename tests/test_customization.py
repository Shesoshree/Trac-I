import sys
import io
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import urllib.request
import json

BASE_URL = "http://127.0.0.1:8000"

def test_threat_profile():
    print("Testing GET /api/threat-profile...")
    req = urllib.request.Request(f"{BASE_URL}/api/threat-profile")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        print("  Active Profile Org:", data["organization_name"])
        print("  Monitored Brands:", data["monitored_brands"])
        print("  Executive Watchlist Count:", len(data["executive_watchlist"]))
        assert "Defense" in data["organization_name"]
        assert len(data["monitored_brands"]) > 0

def test_generate_and_analyze_custom_scenario():
    print("\nTesting POST /api/custom-scenario/generate for M365 Password Expiration...")
    payload = {
        "lure_type": "m365_password_expiry",
        "target_employee_name": "Marcus Vance",
        "target_employee_role": "Principal Cryptographic Lead",
        "target_employee_email": "m.vance@aegis-defense-systems.com",
        "attacker_technique": "homoglyph_cyrillic",
        "custom_subject": "ACTION REQUIRED: Aegis M365 GCC High Password Expiration",
        "urgency_deadline": "90 minutes"
    }
    req = urllib.request.Request(
        f"{BASE_URL}/api/custom-scenario/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        gen_data = json.loads(resp.read().decode())
        print("  Generated Title:", gen_data["title"])
        print("  Target Employee:", gen_data["target_employee"])
        print("  Techniques:", gen_data["technique_tags"])
        raw_eml = gen_data["raw_eml"]
        assert len(raw_eml) > 100
        assert "Marcus Vance" in raw_eml

    print("\nTesting POST /api/analyze/email with generated custom scenario...")
    analyze_req = urllib.request.Request(
        f"{BASE_URL}/api/analyze/email",
        data=json.dumps({"raw_eml": raw_eml}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(analyze_req) as resp:
        assert resp.status == 200
        analysis = json.loads(resp.read().decode())
        pred = analysis["prediction"]
        features = analysis["features"]
        print(f"  Threat Score: {pred['threat_score']}% (Severity: {pred['severity']})")
        print(f"  Category: {pred['category']}")
        print(f"  SOC Action: {pred['soc_action']}")
        print(f"  Total URLs Found: {features['urls']['total_urls_found']}")
        print(f"  Urgency Triggers Count: {features['nlp']['counts']['urgency']}")
        print(f"  Top XAI Contributions: {[c['title'] + ' (+' + str(c['impact_percentage']) + '%)' for c in pred['feature_contributions'][:3]]}")
        assert pred["threat_score"] >= 75
        assert pred["severity"] in ["CRITICAL", "HIGH"]

def test_hr_policy_custom_scenario():
    print("\nTesting POST /api/custom-scenario/generate for Urgent HR Policy Update...")
    payload = {
        "lure_type": "urgent_hr_policy",
        "target_employee_name": "Elena Rostova",
        "target_employee_role": "Senior Propulsion Engineer (Secret)",
        "target_employee_email": "e.rostova@aegis-defense-systems.com",
        "attacker_technique": "all_techniques",
        "urgency_deadline": "close of business today"
    }
    req = urllib.request.Request(
        f"{BASE_URL}/api/custom-scenario/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        gen_data = json.loads(resp.read().decode())
        raw_eml = gen_data["raw_eml"]

    analyze_req = urllib.request.Request(
        f"{BASE_URL}/api/analyze/email",
        data=json.dumps({"raw_eml": raw_eml}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(analyze_req) as resp:
        assert resp.status == 200
        analysis = json.loads(resp.read().decode())
        pred = analysis["prediction"]
        print(f"  HR Policy Threat Score: {pred['threat_score']}%")
        print(f"  Fear / Disciplinary Trigger Count: {analysis['features']['nlp']['counts']['fear']}")
        print(f"  Hidden Anti-Spam Elements: {analysis['features']['dom']['hidden_elements_count']}")
        assert pred["threat_score"] >= 80

if __name__ == "__main__":
    print("--- STARTING DEFENSE CUSTOMIZATION VERIFICATION ---")
    test_threat_profile()
    test_generate_and_analyze_custom_scenario()
    test_hr_policy_custom_scenario()
    print("\n[SUCCESS] All defense customization & simulation tests passed with 100% precision!")
