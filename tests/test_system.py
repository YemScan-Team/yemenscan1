import os
import sys
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
import sys
import requests
import json

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def main():
    base_url = "http://127.0.0.1:8000"
    tests = []

    # 1. Dashboard HTML
    r = requests.get(base_url + "/")
    tests.append(("Dashboard HTML (GET /)", r.status_code == 200, f"Status {r.status_code}"))

    # 2. Scans History
    r = requests.get(base_url + "/api/scans")
    scans_data = r.json() if r.status_code == 200 else {}
    scans = scans_data.get("scans", [])
    tests.append(("List Scans (GET /api/scans)", r.status_code == 200 and len(scans) > 0, f"{len(scans)} scans found"))

    scan_id = scans[0]["scan_id"] if scans else "scan_20260918_004732_dvwa.co.uk"

    # 3. Status
    r = requests.get(f"{base_url}/api/scan/{scan_id}/status")
    tests.append(("Scan Status (GET /api/scan/status)", r.status_code == 200, f"Status {r.status_code}"))

    # 4. Discovery
    r = requests.get(f"{base_url}/api/scan/{scan_id}/discovery")
    sub_count = len(r.json().get("subdomains", []))
    tests.append(("Discovery Results (GET /api/scan/discovery)", r.status_code == 200, f"{sub_count} subdomains"))

    # 5. Endpoints
    r = requests.get(f"{base_url}/api/scan/{scan_id}/endpoints")
    web_count = len(r.json().get("live_web_services", []))
    api_count = len(r.json().get("api_endpoints", []))
    tests.append(("Endpoints & Web (GET /api/scan/endpoints)", r.status_code == 200, f"{web_count} web services, {api_count} APIs"))

    # 6. Vulnerabilities
    r = requests.get(f"{base_url}/api/scan/{scan_id}/vulnerabilities")
    vuln_count = len(r.json().get("vulnerabilities", []))
    tests.append(("Vulnerabilities (GET /api/scan/vulnerabilities)", r.status_code == 200, f"{vuln_count} findings"))

    # 7. Nuclei Info
    r = requests.get(f"{base_url}/api/nuclei/info")
    tpl_count = r.json().get("total_templates", 0)
    tests.append(("Nuclei Engine Info (GET /api/nuclei/info)", r.status_code == 200, f"{tpl_count} templates installed"))

    # 8. AI Report
    r = requests.get(f"{base_url}/api/scan/{scan_id}/ai-report")
    d = r.json() if r.status_code == 200 else {}
    rep_len = len(d.get("ai_report_markdown", ""))
    ai_ok = r.status_code == 200 and d.get("status") == "success" and rep_len > 100
    tests.append(("AI Security Report (GET /api/scan/ai-report)", ai_ok, f"Model: {d.get('model_used')}, Cached: {d.get('cached')}, Length: {rep_len} chars"))

    print("=" * 70)
    print("              YEMENSCAN SYSTEM INTEGRATION VERIFICATION")
    print("=" * 70)
    all_passed = True
    for name, passed, info in tests:
        status_str = "[PASS] [OK]" if passed else "[FAIL] [X]"
        if not passed:
            all_passed = False
        print(f"{status_str} {name:44} -> {info}")
    print("=" * 70)
    print("FINAL RESULT:", "ALL SYSTEMS OPERATIONAL & WORKING PERFECTLY!" if all_passed else "SOME ISSUES DETECTED")

if __name__ == "__main__":
    main()

