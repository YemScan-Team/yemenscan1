import os
import sys
import sqlite3
import requests
import json
from datetime import datetime

BASE_URL = "http://127.0.0.1:8000"

results = {
    "database": {},
    "api_endpoints": {},
    "ai_engine": {},
    "security_validation": {},
    "nuclei_templates": {},
    "scan_pipeline": {}
}

print("=" * 80)
print("             YEMENSCAN COMPREHENSIVE SYSTEM VERIFICATION")
print("=" * 80)

# 1. Database Verification
print("\n[1] VERIFYING DATABASE (yemenscan.db)...")
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
db_path = os.path.join(BASE_DIR, "yemenscan.db")

try:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [r[0] for r in cur.fetchall()]
    table_stats = {}
    for t in tables:
        cur.execute(f"SELECT COUNT(*) FROM {t}")
        table_stats[t] = cur.fetchone()[0]
    conn.close()
    results["database"]["status"] = "OK"
    results["database"]["tables"] = table_stats
    print(f"  [PASS] Database exists and is readable: {len(tables)} tables")
    for t, cnt in table_stats.items():
        print(f"    - {t}: {cnt} records")
except Exception as e:
    results["database"]["status"] = f"FAIL: {e}"
    print(f"  [FAIL] Database error: {e}")

# 2. REST API Endpoints Verification
print("\n[2] VERIFYING REST API ENDPOINTS...")

endpoints_to_test = [
    ("GET", "/", "Dashboard UI Home", 200, "text/html"),
    ("GET", "/docs", "Swagger UI Docs", 200, "text/html"),
    ("GET", "/openapi.json", "OpenAPI Specification", 200, "application/json"),
    ("GET", "/api/scans", "List All Scans", 200, "application/json"),
    ("GET", "/api/nuclei/info", "Nuclei Engine Info", 200, "application/json"),
    ("GET", "/api/target/validate?target=example.com", "Target Validator (Valid domain)", 200, "application/json"),
    ("GET", "/api/target/validate?target=127.0.0.1", "Target Validator (Disallow localhost)", 200, "application/json"),
]

for method, path, desc, expected_code, content_type in endpoints_to_test:
    try:
        url = BASE_URL + path
        if method == "GET":
            r = requests.get(url, timeout=10)
        status_ok = r.status_code == expected_code
        ctype_ok = content_type in r.headers.get("content-type", "")
        passed = status_ok and ctype_ok
        print(f"  {'[PASS]' if passed else '[FAIL]'} {desc} ({method} {path}) -> {r.status_code} (Expected {expected_code})")
        results["api_endpoints"][path] = {"passed": passed, "code": r.status_code}
    except Exception as e:
        print(f"  [FAIL] {desc} ({method} {path}) -> Exception: {e}")
        results["api_endpoints"][path] = {"passed": False, "error": str(e)}

# 3. Specific Scan Details & Exports
print("\n[3] VERIFYING SCAN DETAILS & EXPORTS...")
try:
    r = requests.get(BASE_URL + "/api/scans", timeout=10)
    scans_data = r.json().get("scans", [])
    if scans_data:
        # Find a scan with assets or vulnerabilities if possible
        target_scan_id = scans_data[0]["scan_id"]
        for s in scans_data:
            if s.get("vulnerabilities_count", 0) > 0 or s.get("subdomains_count", 0) > 0:
                target_scan_id = s["scan_id"]
                break
        print(f"  Testing with Scan ID: {target_scan_id}")

        scan_endpoints = [
            ("GET", f"/api/scan/{target_scan_id}/status", "Scan Status"),
            ("GET", f"/api/scan/{target_scan_id}/discovery", "Discovery Results"),
            ("GET", f"/api/scan/{target_scan_id}/endpoints", "Endpoints & Services"),
            ("GET", f"/api/scan/{target_scan_id}/vulnerabilities", "Vulnerability Findings"),
            ("GET", f"/api/scan/{target_scan_id}/report", "Unified Report (JSON)"),
            ("GET", f"/api/scan/{target_scan_id}/results", "Combined Results"),
            ("GET", f"/api/scan/{target_scan_id}/ai-report", "AI Security Report"),
            ("GET", f"/api/scan/{target_scan_id}/export/html", "Export HTML"),
            ("GET", f"/api/scan/{target_scan_id}/export/json", "Export JSON"),
            ("GET", f"/api/scan/{target_scan_id}/export/markdown", "Export Markdown"),
        ]

        for method, path, desc in scan_endpoints:
            try:
                r = requests.get(BASE_URL + path, timeout=15)
                passed = r.status_code == 200
                extra = ""
                if "export" in path:
                    extra = f"Content-Length: {len(r.content)} bytes"
                elif "ai-report" in path:
                    extra = f"Model: {r.json().get('model_used')}"
                elif "vulnerabilities" in path:
                    extra = f"{len(r.json().get('vulnerabilities', []))} vulns"
                print(f"  {'[PASS]' if passed else '[FAIL]'} {desc} ({path}) -> {r.status_code} {extra}")
                results["api_endpoints"][path] = {"passed": passed, "code": r.status_code}
            except Exception as e:
                print(f"  [FAIL] {desc} ({path}) -> Exception: {e}")
                results["api_endpoints"][path] = {"passed": False, "error": str(e)}
    else:
        print("  [WARN] No scans found in system to test details")
except Exception as e:
    print(f"  [FAIL] Failed to list scans: {e}")

# 4. Target Validator Security Check
print("\n[4] VERIFYING TARGET VALIDATION & SECURITY SANITIZATION...")
validation_tests = [
    ("google.com", True, "Valid domain"),
    ("test.co.uk", True, "Valid TLD domain"),
    ("http://sub.domain.com:8080", True, "URL with port"),
    ("127.0.0.1", False, "Loopback IPv4 (Security Disallowed)"),
    ("localhost", False, "Localhost (Security Disallowed)"),
    ("192.168.1.1", False, "Private RFC1918 IP (Security Disallowed)"),
    ("10.0.0.1", False, "Private RFC1918 Class A (Security Disallowed)"),
    ("example.com; cat /etc/passwd", False, "Command Injection attempt"),
    ("example.com && rm -rf /", False, "Command Chaining attempt"),
    ("<script>alert(1)</script>", False, "XSS Payload in domain"),
]

for target, expected_valid, desc in validation_tests:
    try:
        r = requests.post(BASE_URL + "/api/target/validate", json={"domain": target}, timeout=5)
        data = r.json()
        is_valid = data.get("valid", False)
        passed = (is_valid == expected_valid)
        print(f"  {'[PASS]' if passed else '[FAIL]'} {desc} ('{target}') -> Valid: {is_valid} (Expected: {expected_valid})")
        results["security_validation"][target] = passed
    except Exception as e:
        print(f"  [FAIL] {desc} ('{target}') -> Exception: {e}")

# 5. Vulnerability Normalizer Test
print("\n[5] VERIFYING VULNERABILITY NORMALIZATION ENGINE...")
try:
    sample_findings = {
        "nuclei": [
            {
                "template-id": "cve-2021-44228",
                "info": {
                    "name": "Apache Log4j RCE",
                    "severity": "critical",
                    "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP",
                    "remediation": "Upgrade Log4j to 2.15.0 or later"
                },
                "matched-at": "https://example.com/login"
            }
        ],
        "wapiti": [
            {
                "category": "Cross Site Scripting",
                "level": 3,
                "info": "Reflected XSS in search parameter",
                "solution": "Filter and encode output parameter",
                "http_request": "GET /search?q=<script> HTTP/1.1"
            }
        ]
    }
    r = requests.post(BASE_URL + "/api/vulnerabilities/normalize", json=sample_findings, timeout=5)
    if r.status_code == 200:
        norm_data = r.json()
        vulns = norm_data.get("vulnerabilities", [])
        passed = len(vulns) >= 2
        print(f"  {'[PASS]' if passed else '[FAIL]'} Normalize Engine POST -> 200 OK ({len(vulns)} normalized vulnerabilities)")
        for v in vulns:
            print(f"    - [{v.get('severity', 'UNKNOWN').upper()}] {v.get('title') or v.get('name')} (Source: {v.get('source')})")
    else:
        print(f"  [FAIL] Normalize Engine failed with status {r.status_code}")
except Exception as e:
    print(f"  [FAIL] Normalize Engine exception: {e}")

# 6. Nuclei Templates Inspection
print("\n[6] VERIFYING NUCLEI TEMPLATES INTEGRATION...")
try:
    r = requests.get(BASE_URL + "/api/nuclei/info", timeout=5)
    if r.status_code == 200:
        data = r.json()
        total_tpl = data.get("total_templates", 0)
        categories = data.get("categories", {})
        print(f"  [PASS] Nuclei Engine Active: {total_tpl} templates available")
        for cat, count in categories.items():
            print(f"    * {cat}: {count} templates")
    else:
        print(f"  [FAIL] Nuclei Info returned status {r.status_code}")
except Exception as e:
    print(f"  [FAIL] Nuclei Info exception: {e}")

# 7. Check Tools Availability on System
print("\n[7] VERIFYING OS & SECURITY TOOLS AVAILABILITY...")
import shutil
tools = ["docker", "subfinder", "naabu", "httpx", "kiterunner", "kr", "nuclei", "wapiti"]
for tool in tools:
    path = shutil.which(tool)
    if path:
        print(f"  [FOUND] {tool:12} -> {path}")
    else:
        print(f"  [SIMULATED/NOT IN PATH] {tool:12} (System uses containerized/docker or fallback runner)")

print("\n" + "=" * 80)
print("                    VERIFICATION SUMMARY COMPLETED")
print("=" * 80)
