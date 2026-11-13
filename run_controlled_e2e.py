import os
import sys
import time
import json
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

os.environ["YEMENSCAN_USE_DOCKER"] = "1"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from core.stage3_vulnerabilities import (
    verify_wapiti_image_identity,
    WapitiImageIdentityError,
    WAPITI_DOCKER_IMAGE,
    WAPITI_EXPECTED_IMAGE_ID,
    WAPITI_ENGINE_VERSION,
    WAPITI_REPO_DIGEST,
    NUCLEI_DOCKER_IMAGE,
    NUCLEI_RUNTIME_TEMPLATES_DIR,
    run_wapiti_dast,
    parse_wapiti_json_output,
    run_nuclei,
    unify_and_save_vulnerabilities
)
from core.security_scan_planner import (
    SecurityScanPlanner,
    WAPITI_SAFE_MODULES
)
from core.runner import run_docker_tool

# Request tracking for controlled server
REQUEST_LOG = []
SERVER_PORT = 8888

class ControlledHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Quiet standard logging to keep test output clean
        pass

    def do_GET(self):
        REQUEST_LOG.append({
            "method": "GET",
            "path": self.path,
            "headers": dict(self.headers),
            "timestamp": time.time()
        })
        
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            # Cookie missing Secure and HttpOnly flags
            self.send_header("Set-Cookie", "sessionid=controlled_test_token_98765; Path=/")
            # Intentionally missing HSTS and CSP
            self.end_headers()
            body = """<!DOCTYPE html>
<html>
<head><title>Controlled Target</title></head>
<body>
  <h1>YemenScan Controlled Test Target</h1>
  <p>Safe non-exploitable local test fixture.</p>
  <ul>
    <li><a href="/login">Login</a></li>
    <li><a href="/status">Server Status</a></li>
    <li><a href="/debug/err">Exception Trace</a></li>
    <li><a href="/redirect">Inconsistent Redirection</a></li>
  </ul>
</body>
</html>"""
            self.wfile.write(body.encode("utf-8"))

        elif path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.end_headers()
            # Cleartext password submission form pointing to unencrypted HTTP
            body = """<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
  <h2>User Login</h2>
  <form method="post" action="http://host.docker.internal:8888/login">
    <label>Username: <input type="text" name="username"></label><br>
    <label>Password: <input type="password" name="password"></label><br>
    <input type="submit" value="Sign In">
  </form>
</body>
</html>"""
            self.wfile.write(body.encode("utf-8"))

        elif path == "/status":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.send_header("X-Powered-By", "PHP/7.4.3")
            self.end_headers()
            body = "<html><body>Apache/2.4.41 (Ubuntu) Server at localhost Port 8888</body></html>"
            self.wfile.write(body.encode("utf-8"))

        elif path == "/debug/err":
            self.send_response(500)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.end_headers()
            body = """<html><body>
<h1>500 Internal Server Error</h1>
<pre>Traceback (most recent call last):
  File "/var/app/controller.py", line 42, in handle_request
    conn = database.connect("db://localhost")
ConnectionRefusedError: [Errno 111] Connection refused</pre>
</body></html>"""
            self.wfile.write(body.encode("utf-8"))

        elif path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://host.docker.internal:8888/status")
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.end_headers()

        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body>404 Not Found</body></html>")

    def do_POST(self):
        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len).decode("utf-8", errors="replace") if content_len > 0 else ""
        REQUEST_LOG.append({
            "method": "POST",
            "path": self.path,
            "body": body,
            "headers": dict(self.headers),
            "timestamp": time.time()
        })
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<html><body>POST Received</body></html>")

def start_server():
    server = HTTPServer(("0.0.0.0", SERVER_PORT), ControlledHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    return server

def main():
    print("=" * 75)
    print("      YEMENSCAN CONTROLLED E2E INTEGRATION TEST (NUCLEI -> WAPITI)")
    print("=" * 75)

    session_dir = os.path.join(BASE_DIR, "output", "controlled_e2e_session")
    os.makedirs(session_dir, exist_ok=True)
    scan_id = "controlled-e2e-001"

    # Step 1: Image Identity Verification
    print("[1] Verifying Wapiti Docker Image Identity (Fail Closed)...")
    is_valid = verify_wapiti_image_identity(WAPITI_DOCKER_IMAGE, WAPITI_EXPECTED_IMAGE_ID)
    print(f"    - WAPITI_DOCKER_IMAGE:     {WAPITI_DOCKER_IMAGE}")
    print(f"    - WAPITI_EXPECTED_IMAGE_ID: {WAPITI_EXPECTED_IMAGE_ID}")
    print(f"    - Verification Result:     {'PASSED (Verified)' if is_valid else 'FAILED'}")
    assert is_valid, "Wapiti image identity verification failed!"

    # Step 2: Version Check
    print("\n[2] Executing Wapiti --version in container...")
    ok, ver_out = run_docker_tool(
        image=WAPITI_DOCKER_IMAGE,
        args=["--version"],
        volume_dir=session_dir,
        timeout=60
    )
    print(f"    - Exit Code: {'0 (Success)' if ok else 'Non-Zero'}")
    print(f"    - Output:    {ver_out.strip()}")
    assert "3.3.2" in ver_out, f"Wapiti version mismatch! Output: {ver_out}"

    # Step 3: Start Controlled Server
    print(f"\n[3] Starting Controlled Local Web Server on 0.0.0.0:{SERVER_PORT}...")
    server = start_server()
    time.sleep(1)
    target_origin = f"http://host.docker.internal:{SERVER_PORT}"
    print(f"    - Local Target Origin: {target_origin}")
    print("    - Active Flavors Exposed: Missing HSTS, Missing CSP, Cookie No-Secure/No-HttpOnly,")
    print("      Server Banner Disclosure, Stacktrace Disclosure, Inconsistent Redirection,")
    print("      Cleartext Password Submission Form.")

    # Step 4: Security Scan Planner & Joint Scan Plan
    print("\n[4] Generating Joint Scan Plan via SecurityScanPlanner...")
    planner = SecurityScanPlanner()
    joint_plan = planner.generate_joint_scan_plan(
        session_dir=session_dir,
        origins=[target_origin],
        wapiti_profile="safe",
        verify_ssl=True
    )
    print(f"    - Execution Order: {joint_plan['coordination_policy']['execution_order']}")
    print(f"    - Duplicate Families: {joint_plan['duplicate_capability_families']}")
    print(f"    - Max Active Scanners Per Origin: {joint_plan['coordination_policy']['max_active_security_scanners_per_origin']}")

    # Step 5: Execute Nuclei against local target
    print("\n[5] Executing Nuclei Engine (Sequential Step 1)...")
    nuclei_targets_file = os.path.join(session_dir, "nuclei_targets.txt")
    with open(nuclei_targets_file, "w", encoding="utf-8") as nf:
        nf.write(f"{target_origin}\n")

    nuclei_start = time.time()
    ok_nuclei, nuclei_findings = run_nuclei(session_dir, scan_id)
    nuclei_end = time.time()
    print(f"    - Nuclei Start:    {nuclei_start:.4f}")
    print(f"    - Nuclei End:      {nuclei_end:.4f}")
    print(f"    - Duration:        {nuclei_end - nuclei_start:.2f}s")
    print(f"    - Findings Count:  {len(nuclei_findings)}")

    # Step 6: Execute Wapiti against local target
    print("\n[6] Executing Wapiti DAST Safe Profile (Sequential Step 2)...")
    requests_before_wapiti = len(REQUEST_LOG)
    print(f"    - Total Server Requests before Wapiti: {requests_before_wapiti}")

    wapiti_start = time.time()
    # Enforce sequential coordination check
    assert nuclei_end <= wapiti_start, "Sequential coordination violated: Nuclei did not complete before Wapiti!"
    print("    - Strict Sequential Coordination Verified: nuclei_end <= wapiti_start")

    ok_wapiti, wapiti_findings = run_wapiti_dast(
        session_dir=session_dir,
        scan_id=scan_id,
        primary_urls=[target_origin],
        profile="safe",
        verify_ssl=True
    )
    wapiti_end = time.time()
    requests_after_wapiti = len(REQUEST_LOG)

    print(f"    - Wapiti Start:    {wapiti_start:.4f}")
    print(f"    - Wapiti End:      {wapiti_end:.4f}")
    print(f"    - Duration:        {wapiti_end - wapiti_start:.2f}s")
    print(f"    - Total Server Requests after Wapiti: {requests_after_wapiti}")
    print(f"    - Net Requests Generated by Wapiti:   {requests_after_wapiti - requests_before_wapiti}")

    # Step 7: Analyze Server Request Ledger to Prove Read-Only Passive Crawl & Zero Form Submissions
    print("\n[7] Verifying Server Request Ledger & Non-Mutating Safe Crawl...")
    print("    - Full Server-Side Request Ledger:")
    for idx, req in enumerate(REQUEST_LOG, start=1):
        print(f"      [{idx:02d}] {req['method']} {req['path']} (body size: {len(req.get('body', ''))})")

    # Assert 1: All requests must be GET or HEAD
    non_get_head = [r for r in REQUEST_LOG if r["method"] not in {"GET", "HEAD"}]
    print(f"    - Non-GET/HEAD Requests: {len(non_get_head)}")
    assert len(non_get_head) == 0, f"Violation! Found non-GET/HEAD requests: {non_get_head}"

    # Assert 2: POST count must be exactly zero
    post_requests = [r for r in REQUEST_LOG if r["method"] == "POST"]
    print(f"    - Total POST Requests:   {len(post_requests)}")
    assert len(post_requests) == 0, "Violation! POST request sent during safe crawl!"

    # Assert 3: PUT, PATCH, DELETE must be zero
    mutating_requests = [r for r in REQUEST_LOG if r["method"] in {"PUT", "PATCH", "DELETE"}]
    assert len(mutating_requests) == 0, "Violation! Mutating request sent during safe crawl!"

    # Assert 4: Zero request bodies
    requests_with_body = [r for r in REQUEST_LOG if len(r.get("body", "")) > 0]
    print(f"    - Requests with Body:    {len(requests_with_body)}")
    assert len(requests_with_body) == 0, "Violation! Request body dispatched during safe crawl!"

    print("    - CONFIRMED: Safe Profile is 100% Read-Only! (GET/HEAD only, 0 POSTs, 0 request bodies)!")

    # Step 8: Breakdown Findings Per Module & Verify unsecure_password Discovery
    raw_path = os.path.join(session_dir, "wapiti_raw_1.json")
    assert os.path.exists(raw_path), "wapiti_raw_1.json was not generated by container!"
    with open(raw_path, "r", encoding="utf-8") as rf:
        raw_data = json.load(rf)

    print("\n[8] Wapiti Findings Breakdown Per Safe Passive Module:")
    categories = raw_data.get("vulnerabilities", {})
    for cat_name, occs in categories.items():
        print(f"    - {cat_name:<35}: {len(occs)} finding(s)")

    # Assert 5: unsecure_password MUST still be detected from HTML parsing
    pwd_findings = [f for f in wapiti_findings if f["coverage_family"] == "cleartext_password_submission"]
    print(f"    - Cleartext Password Findings: {len(pwd_findings)}")
    assert len(pwd_findings) >= 1, "Cleartext Submission of Password finding was missed!"
    print(f"      -> Found: {pwd_findings[0]['title']} at {pwd_findings[0]['url']} (Severity: {pwd_findings[0]['severity']})")
    print("    - CONFIRMED: Form parsed from HTML and finding generated with zero form submission!")

    # Step 9: Verify Crawl Policy Telemetry in Metadata
    meta_path = os.path.join(session_dir, "wapiti_metadata.json")
    with open(meta_path, "r", encoding="utf-8") as mf:
        meta_data = json.load(mf)
    print("\n[9] Wapiti Metadata & Crawl Policy Telemetry:")
    print(f"    - Engine Version:                {meta_data.get('version')}")
    print(f"    - Build Variant:                 {meta_data.get('build_variant')}")
    print(f"    - Patches Applied:               {meta_data.get('patches')}")
    print(f"    - Crawl Policy:                  {meta_data.get('crawl_policy')}")
    print(f"    - Allowed HTTP Methods:          {meta_data.get('allowed_http_methods')}")
    print(f"    - Form Submission Enabled:       {meta_data.get('form_submission_enabled')}")
    print(f"    - Blocked Crawler Request Count: {meta_data.get('blocked_crawler_request_count')}")
    print(f"    - Blocked Method Counts:         {meta_data.get('blocked_method_counts')}")

    assert meta_data.get("crawl_policy") == "read_only"
    assert meta_data.get("allowed_http_methods") == ["GET", "HEAD"]
    assert meta_data.get("form_submission_enabled") is False
    assert meta_data.get("blocked_crawler_request_count", 0) >= 1
    assert meta_data.get("blocked_method_counts", {}).get("POST", 0) >= 1

    # Step 10: Unify Findings
    print("\n[10] Unifying and Deduplicating Findings...")
    unified = unify_and_save_vulnerabilities(session_dir, scan_id, nuclei_findings, wapiti_findings)
    print(f"    - Total Unified Findings: {len(unified)}")
    for u in unified:
        print(f"      [{u['severity']}] {u['title']} (Family: {u['coverage_family']}, Sources: {u['sources']})")

    # Step 11: Verify Artifact Files
    print("\n[11] Verifying Generated Artifacts:")
    for f in ["joint_scan_plan.json", "wapiti_raw.json", "wapiti_findings.json", "wapiti_metadata.json", "unified_vulnerabilities.json"]:
        fpath = os.path.join(session_dir, f)
        exists = os.path.exists(fpath)
        sz = os.path.getsize(fpath) if exists else 0
        print(f"    - {f:<30}: {'EXISTS' if exists else 'MISSING'} ({sz} bytes)")
        assert exists and sz > 0, f"Artifact {f} is missing or empty!"

    # Step 12: DAST-Light Verification (Separation & Non-Default)
    print("\n[12] Verifying DAST-Light Separation & Non-Default Invariant:")
    dast_light_plan = planner.generate_joint_scan_plan(
        session_dir=session_dir,
        origins=[target_origin],
        wapiti_profile="dast_light"
    )
    dl_wp = dast_light_plan["wapiti_plan"]
    print(f"    - DAST-Light Profile:            {dl_wp['profile']}")
    print(f"    - DAST-Light Crawl Policy:       {dl_wp['crawl_policy']}")
    print(f"    - DAST-Light Form Submission:    {dl_wp['form_submission_enabled']}")
    print(f"    - DAST-Light Allowed Methods:    {dl_wp['allowed_http_methods']}")
    assert dl_wp["profile"] == "dast_light"
    assert dl_wp["form_submission_enabled"] is True
    assert dl_wp["crawl_policy"] == "standard"
    assert "POST" in dl_wp["allowed_http_methods"]

    # Re-verify default invariant (calling without explicit profile parameter)
    default_plan = planner.generate_joint_scan_plan(session_dir=session_dir, origins=[target_origin])
    def_wp = default_plan["wapiti_plan"]
    print(f"    - Default Planner Profile:       {def_wp['profile']}")
    print(f"    - Default Form Submission:       {def_wp['form_submission_enabled']}")
    assert def_wp["profile"] == "safe"
    assert def_wp["form_submission_enabled"] is False
    assert def_wp["crawl_policy"] == "read_only"
    print("    - CONFIRMED: DAST-Light requires explicit user opt-in and is strictly non-default!")

    server.shutdown()
    print("\n[+] Controlled E2E Integration Run successfully completed!")

if __name__ == "__main__":
    main()
