import os
import sys

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import json
import time
import shutil
import socket
import tempfile
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from core.stage2_web_probing import run_kiterunner_or_api_probing

received_requests = []

class MockApiHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress standard logging to keep output clean
        pass

    def do_GET(self):
        self._record_and_respond("GET")

    def do_POST(self):
        self._record_and_respond("POST")

    def do_PUT(self):
        self._record_and_respond("PUT")

    def do_DELETE(self):
        self._record_and_respond("DELETE")

    def _record_and_respond(self, method):
        xff = self.headers.get("X-Forwarded-For")
        received_requests.append({
            "method": method,
            "path": self.path,
            "xff": xff,
            "headers": dict(self.headers)
        })

        clean_path = self.path.split("?")[0]
        if clean_path == '/api/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', '16')
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
        elif clean_path == '/api/users':
            if method == "GET":
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', '24')
                self.end_headers()
                self.wfile.write(b'{"error": "unauthorized"}')
            elif method == "POST":
                self.send_response(405)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', '30')
                self.end_headers()
                self.wfile.write(b'{"error": "method not allowed"}')
            else:
                self.send_response(405)
                self.end_headers()
        elif clean_path == '/random':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', '22')
            self.end_headers()
            self.wfile.write(b'{"message": "random"}')
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', '22')
            self.end_headers()
            self.wfile.write(b'{"error": "notfound"}')

def run_integration_test():
    port = 8899
    server = HTTPServer(("0.0.0.0", port), MockApiHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    print(f"[+] Mock HTTP Server started on 0.0.0.0:{port}")

    session_dir = os.path.join(BASE_DIR, "output", "test_local_integration")
    os.makedirs(session_dir, exist_ok=True)
    test_wordlist = os.path.join(BASE_DIR, "tests", "fixtures", "routes-test.kite")
    target_url = f"http://host.docker.internal:{port}"

    print(f"[+] Running Kiterunner integration test against {target_url} with {test_wordlist}...")
    try:
        success, candidates = run_kiterunner_or_api_probing(
            active_urls=[target_url],
            session_dir=session_dir,
            scan_id="integ_test_kr",
            custom_wordlist=test_wordlist
        )
        print(f"[+] Execution completed: success={success}, candidates={len(candidates)}")
        # Artifact checks
        input_file = os.path.join(session_dir, "kiterunner_input.txt")
        raw_file = os.path.join(session_dir, "kiterunner_raw.jsonl")
        stderr_file = os.path.join(session_dir, "kiterunner_stderr.log")
        meta_file = os.path.join(session_dir, "kiterunner_metadata.json")
        endpoints_json = os.path.join(session_dir, "api_endpoints.json")
        endpoints_txt = os.path.join(session_dir, "api_endpoints.txt")

        with open(raw_file, "r", encoding="utf-8") as rf:
            print(f"[DEBUG raw_file content]:\n{rf.read()}")

        if os.path.exists(stderr_file):
            with open(stderr_file, "r", encoding="utf-8", errors="replace") as sf:
                print(f"[DEBUG stderr_file]:\n{sf.read()}")
        if os.path.exists(meta_file):
            with open(meta_file, "r", encoding="utf-8", errors="replace") as mf:
                print(f"[DEBUG meta_file]:\n{mf.read()}")

        assert os.path.exists(input_file), "kiterunner_input.txt missing"
        assert os.path.exists(raw_file), "kiterunner_raw.jsonl missing"
        assert os.path.exists(stderr_file), "kiterunner_stderr.log missing"
        assert os.path.exists(meta_file), "kiterunner_metadata.json missing"
        assert os.path.exists(endpoints_json), "api_endpoints.json missing"
        assert os.path.exists(endpoints_txt), "api_endpoints.txt missing"

        with open(meta_file, "r", encoding="utf-8") as f:
            metadata = json.load(f)

        print("[+] Metadata:")
        print(json.dumps(metadata, indent=2))

        # Check invariants
        assert metadata["raw_event_count"] == metadata["parsed_event_count"] + metadata["invalid_event_count"], "Event count invariant violated"
        assert metadata["response_record_count"] == metadata["valid_count"] + metadata["invalid_response_count"] + metadata["duplicate_count"], "Response count invariant violated"
        assert metadata["candidate_count"] == metadata["valid_count"] == len(candidates), "Candidate count invariant violated"
        assert metadata["build_variant"] == "yemscan1", "Build variant mismatch"
        assert metadata["upstream_version"] == "v1.0.2", "Upstream version mismatch"
        assert metadata["upstream_commit"] == "e7a7fa6", "Upstream commit mismatch"
        assert metadata["patches"] == ["remove-default-x-forwarded-for"], "Patches mismatch"

        print(f"[+] Discovered candidates: {len(candidates)}")
        for c in candidates:
            print(f"    - {c['method']} {c['url']} [{c['status_code']}] length={c.get('length')}")

        # Check that XFF 127.0.0.1 was never received
        xff_detected = [r for r in received_requests if r.get("xff") == "127.0.0.1"]
        print(f"[+] Total HTTP requests received: {len(received_requests)}")
        for r in received_requests[:25]:
            print(f"    -> {r['method']} {r['path']}")
        print(f"[+] Requests with X-Forwarded-For: 127.0.0.1: {len(xff_detected)}")
        assert len(xff_detected) == 0, "Default X-Forwarded-For was sent by Kiterunner!"

        print("[SUCCESS] Controlled Local Integration Test PASSED completely!")
        return 0
    except Exception as e:
        import traceback
        print(f"[FAIL] Integration test failed: {e}")
        traceback.print_exc()
        return 1
    finally:
        server.shutdown()
        shutil.rmtree(session_dir, ignore_errors=True)

if __name__ == "__main__":
    sys.exit(run_integration_test())
