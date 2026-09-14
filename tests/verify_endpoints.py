"""Verify all live API endpoints and web pages."""
import json
import sys
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def test_endpoint(url, data=None):
    headers = {'Content-Type': 'application/json'}
    payload = json.dumps(data).encode('utf-8') if data else None
    req = urllib.request.Request(url, data=payload, headers=headers)
    with urllib.request.urlopen(req) as resp:
        return resp.status, resp.read().decode('utf-8')

def main():
    # 1. Test HTML Pages
    for path in ['/', '/extension', '/scan', '/disposable', '/how-it-works']:
        status, body = test_endpoint(f'http://127.0.0.1:8000{path}')
        print(f'Page {path}: HTTP {status} (Length: {len(body)} bytes)')

    # 2. Test Scenarios API
    status, scens = test_endpoint('http://127.0.0.1:8000/api/scenarios')
    scen_list = json.loads(scens)
    print(f'API /api/scenarios: HTTP {status} ({len(scen_list)} scenarios available)')

    # 3. Test Disposable Email API
    status, disp = test_endpoint('http://127.0.0.1:8000/api/check-disposable', {'email_or_domain': 'test@mailinator.com'})
    d_data = json.loads(disp)
    print(f"API /api/check-disposable: HTTP {status} -> is_disposable: {d_data['is_disposable']}, category: {d_data['category']}")

    # 4. Test URL Analysis API
    status, ures = test_endpoint('http://127.0.0.1:8000/api/analyze/url', {'url': 'https://xn--cmmc-d-81a.xyz/portal/verify'})
    u_data = json.loads(ures)
    print(f"API /api/analyze/url: HTTP {status} -> Risk: {u_data['risk_score']}%, Punycode: {u_data['is_punycode']}")

    # 5. Test Email Analysis API
    first_scen = scen_list[0]['id']
    _, scen_detail = test_endpoint(f'http://127.0.0.1:8000/api/scenarios/{first_scen}')
    scen_obj = json.loads(scen_detail)

    status, email_res = test_endpoint('http://127.0.0.1:8000/api/analyze/email', {'raw_eml': scen_obj['raw_eml']})
    e_data = json.loads(email_res)
    pred = e_data['prediction']
    print(f"API /api/analyze/email: HTTP {status} -> Score: {pred['threat_score']}%, Severity: {pred['severity']}, Category: {pred['category']}")

    # 6. Test Sandbox API
    status, sb_res = test_endpoint('http://127.0.0.1:8000/api/analyze/sandbox', {'url': 'https://login-micrоsoft365-verify.com/login.srf'})
    sb_data = json.loads(sb_res)
    print(f"API /api/analyze/sandbox: HTTP {status} -> Title: {sb_data['page_title']}, FormAction: {sb_data['form_action']}")

    # 7. Test Extension Download
    req = urllib.request.Request('http://127.0.0.1:8000/api/download/extension')
    with urllib.request.urlopen(req) as resp:
        zip_bytes = resp.read()
    # 8. Test Model Metrics API
    status, m_res = test_endpoint('http://127.0.0.1:8000/api/model/metrics')
    m_data = json.loads(m_res)
    print(f"API /api/model/metrics: HTTP {status} -> Features: {m_data.get('features_count')}, Acc: {m_data.get('accuracy')}")

    # 9. Test Scan History API
    status, h_res = test_endpoint('http://127.0.0.1:8000/api/history')
    h_data = json.loads(h_res)
    print(f"API /api/history: HTTP {status} -> Recorded Scans: {len(h_data)}")

    # 10. Test Incident Export API
    status, exp_res = test_endpoint('http://127.0.0.1:8000/api/export/incident/apt_hr_policy_update')
    exp_data = json.loads(exp_res)
    print(f"API /api/export/incident: HTTP {status} -> Incident ID: {exp_data.get('incident_id')}")

    print("\nALL 10 LIVE SYSTEM VERIFICATION CHECKS PASSED!")

if __name__ == '__main__':
    main()
