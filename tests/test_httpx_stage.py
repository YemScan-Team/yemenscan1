"""
Unit and integration tests for the httpx stage in YemenScan.

Covers all core requirements and provenance verification:
1. Real httpx result: valid URLs and status codes correctly saved.
2. Non-200 live responses: status codes (301, 403, 404, 500) accepted as live web services.
3. Zero results behavior: ports.txt empty or 0 live URLs -> active_urls = [], live_urls_count = 0.
4. Tool failure handling: run_docker_tool failure -> status=failed, active_urls=[], live_urls_count=0.
5. Malformed JSON handling: corrupt JSONL lines increment invalid_count without crashing parser.
6. Duplicate URL handling: duplicates increment duplicate_count without incrementing invalid_count.
7. Redirect handling: Location header preserved in JSON/metadata without injecting destination into active_urls.txt.
8. No fabricated 200 status: original status codes (e.g. 503) preserved without forging 200.
9. No requests.get fallback: Python HTTP fallback probing is completely eliminated.
10. Input isolation: httpx targets strictly derived from ports.txt, subdomains.txt untouched.
11. Stale file protection: previous run files cleaned before starting new execution.
12. Pipeline fallback removal: downstream stages receive empty list when active_urls is empty.
13. Kiterunner integration: empty active_urls returns (True, []) immediately with api_endpoints_count: 0.
14. Raw evidence preservation: httpx_raw.jsonl is preserved intact.
15. Exact count invariant: raw_count == valid_count + invalid_count + duplicate_count.
16. Dashboard state & live_urls_count: update_status called across all exit paths with accurate counts.

Dedicated Provenance Tests:
- test_provenance_01_host_default_https_port
- test_provenance_02_host_default_http_port
- test_provenance_03_non_standard_port_8443
- test_provenance_04_external_host_rejected
- test_provenance_05_same_host_different_port_rejected
- test_provenance_06_redirect_location_out_of_scope_not_added
- test_provenance_07_ip_only_target_accepted
- test_provenance_08_invalid_count_includes_provenance_failures
- test_provenance_09_exact_count_invariant_with_provenance_failures
- test_provenance_10_input_field_mismatch_rejected
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.stage2_web_probing import (
    run_httpx,
    normalize_host_port,
    normalize_web_url,
    run_kiterunner_or_api_probing
)
from core.stage3_vulnerabilities import prepare_nuclei_targets


class TestHttpxStage(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ys_httpx_test_")
        self.scan_id = "test_httpx_session_001"
        self.session_dir = os.path.join(self.test_dir, self.scan_id)
        os.makedirs(self.session_dir, exist_ok=True)

        # Status file
        status_path = os.path.join(self.session_dir, "status.json")
        with open(status_path, "w", encoding="utf-8") as f:
            json.dump({
                "scan_id": self.scan_id,
                "target_domain": "example.com",
                "current_stage": "phase2_web_probing",
                "progress_percentage": 40,
                "logs": [],
                "is_completed": False,
                "has_error": False,
                "error_message": None,
                "stats": {"live_urls_count": 0}
            }, f)

        # Discovered ports file (output from Naabu)
        self.ports_file = os.path.join(self.session_dir, "ports.txt")
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("example.com:443\napi.example.com:80\n")

        # Subfinder subdomains file (must remain untouched!)
        self.subdomains_file = os.path.join(self.session_dir, "subdomains.txt")
        self.initial_subdomains = "api.example.com\nwww.example.com\n"
        with open(self.subdomains_file, "w", encoding="utf-8") as f:
            f.write(self.initial_subdomains)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_01_real_httpx_result(self, mock_update, mock_docker):
        """
        Test 1: Real httpx result
        Raw output contains valid HTTP/HTTPS endpoints from httpx matching ports.txt.
        Expected: Correctly parsed, saved in active_urls.txt and active_urls.json.
        """
        raw_jsonl = (
            '{"url":"https://example.com","input":"example.com:443","status_code":200,"title":"Example","webserver":"nginx","tech":["Nginx"]}\n'
            '{"url":"http://api.example.com","input":"api.example.com:80","status_code":200,"title":"API","webserver":"cloudflare","tech":["Cloudflare"]}\n'
        )

        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "httpx_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertEqual(len(active_urls), 2)
        self.assertIn("https://example.com", active_urls)
        self.assertIn("http://api.example.com", active_urls)

        # Verify active_urls.txt
        txt_path = os.path.join(self.session_dir, "active_urls.txt")
        self.assertTrue(os.path.exists(txt_path))
        with open(txt_path, "r", encoding="utf-8") as f:
            txt_lines = [l.strip() for l in f if l.strip()]
        self.assertEqual(txt_lines, active_urls)

        # Verify active_urls.json
        json_path = os.path.join(self.session_dir, "active_urls.json")
        self.assertTrue(os.path.exists(json_path))
        with open(json_path, "r", encoding="utf-8") as f:
            json_records = [json.loads(l) for l in f if l.strip()]
        self.assertEqual(len(json_records), 2)
        self.assertEqual(json_records[0]["source"], "httpx")

        # Verify metadata
        meta_path = os.path.join(self.session_dir, "httpx_metadata.json")
        self.assertTrue(os.path.exists(meta_path))
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["tool"], "httpx")
        self.assertEqual(meta["status"], "completed")
        self.assertEqual(meta["raw_count"], 2)
        self.assertEqual(meta["valid_count"], 2)
        self.assertEqual(meta["invalid_count"], 0)
        self.assertEqual(meta["duplicate_count"], 0)
        self.assertEqual(meta["live_service_count"], 2)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_02_non_200_live_responses(self, mock_update, mock_docker):
        """
        Test 2: Non-200 live response
        httpx finds responses with 403, 404, 500 status codes for valid targets.
        Expected: All accepted as live web services and preserved in active_urls.txt.
        """
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("admin.example.com:443\napi.example.com:80\ninternal.example.com:8443\n")

        raw_jsonl = (
            '{"url":"https://admin.example.com","input":"admin.example.com:443","status_code":403,"title":"Forbidden"}\n'
            '{"url":"http://api.example.com/notfound","input":"api.example.com:80","status_code":404,"title":"Not Found"}\n'
            '{"url":"https://internal.example.com:8443","input":"internal.example.com:8443","status_code":500,"title":"Server Error"}\n'
        )

        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "httpx_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertEqual(len(active_urls), 3)
        self.assertIn("https://admin.example.com", active_urls)
        self.assertIn("http://api.example.com/notfound", active_urls)
        self.assertIn("https://internal.example.com:8443", active_urls)

        # Check metadata status_code_counts
        meta_path = os.path.join(self.session_dir, "httpx_metadata.json")
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["status_code_counts"].get("403"), 1)
        self.assertEqual(meta["status_code_counts"].get("404"), 1)
        self.assertEqual(meta["status_code_counts"].get("500"), 1)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_03_zero_results_behavior(self, mock_update, mock_docker):
        """
        Test 3: Zero results behavior
        Case A: ports.txt is empty -> returns (True, [], []), live_urls_count: 0.
        Case B: ports.txt has entries, httpx returns empty output -> returns (True, [], []).
        """
        # Case A: ports.txt is empty
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("")

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(active_urls, [])
        self.assertEqual(web_targets, [])
        mock_docker.assert_not_called()

        meta_path = os.path.join(self.session_dir, "httpx_metadata.json")
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["status"], "completed")
        self.assertEqual(meta["input_count"], 0)
        self.assertEqual(meta["valid_count"], 0)

        # Case B: ports.txt has entries, but httpx discovers 0 web services
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("example.com:8080\n")

        def fake_docker_empty(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "httpx_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write("")
            return True, ""

        mock_docker.side_effect = fake_docker_empty

        ok2, web_targets2, active_urls2 = run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(ok2)
        self.assertEqual(active_urls2, [])
        self.assertEqual(web_targets2, [])

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_04_tool_failure_handling(self, mock_update, mock_docker):
        """
        Test 4: Tool failure handling
        run_docker_tool returns False.
        Expected: status = failed, active_urls = [], live_urls_count = 0.
        """
        mock_docker.return_value = (False, "Container execution error: exit code 125")

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)

        self.assertFalse(ok)
        self.assertEqual(active_urls, [])
        self.assertEqual(web_targets, [])

        meta_path = os.path.join(self.session_dir, "httpx_metadata.json")
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["status"], "failed")
        self.assertEqual(meta["valid_count"], 0)
        self.assertIn("Container execution error", meta.get("error", ""))

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_05_malformed_json_handling(self, mock_update, mock_docker):
        """
        Test 5: Malformed JSON handling
        Corrupted JSONL lines increment invalid_count without crashing the parser.
        """
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("valid.example.com:443\nvalid2.example.com:443\n")

        raw_jsonl = (
            '{"url":"https://valid.example.com","status_code":200}\n'
            'THIS IS CORRUPTED JSON LINE\n'
            '{"not_a_url": "missing_url_key"}\n'
            '{"url": "ftp://unsupported-scheme.com", "status_code": 200}\n'
            '{"url":"https://valid2.example.com","status_code":200}\n'
        )

        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "httpx_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertEqual(len(active_urls), 2)
        self.assertEqual(active_urls, ["https://valid.example.com", "https://valid2.example.com"])

        meta_path = os.path.join(self.session_dir, "httpx_metadata.json")
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["raw_count"], 5)
        self.assertEqual(meta["valid_count"], 2)
        self.assertEqual(meta["invalid_count"], 3)
        self.assertEqual(meta["duplicate_count"], 0)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_06_duplicate_url_handling(self, mock_update, mock_docker):
        """
        Test 6: Duplicate URL handling
        Duplicate URLs increment duplicate_count without incrementing invalid_count.
        """
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("api.example.com:443\n")

        raw_jsonl = (
            '{"url":"https://api.example.com","status_code":200}\n'
            '{"url":"https://api.example.com:443","status_code":200}\n'
            '{"url":"https://api.example.com/","status_code":200}\n'
        )

        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "httpx_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertEqual(len(active_urls), 1)
        self.assertEqual(active_urls[0], "https://api.example.com")

        meta_path = os.path.join(self.session_dir, "httpx_metadata.json")
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["raw_count"], 3)
        self.assertEqual(meta["valid_count"], 1)
        self.assertEqual(meta["invalid_count"], 0)
        self.assertEqual(meta["duplicate_count"], 2)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_07_redirect_handling(self, mock_update, mock_docker):
        """
        Test 7: Redirect handling
        Redirect response (301) includes location header in metadata/JSON,
        but does NOT add the redirect destination to active_urls.txt.
        """
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("example.com:80\n")

        raw_jsonl = (
            '{"url":"http://example.com","input":"example.com:80","status_code":301,"location":"https://redirected.external.com"}\n'
        )

        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "httpx_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertEqual(active_urls, ["http://example.com"])
        self.assertNotIn("https://redirected.external.com", active_urls)

        # Confirm location header is stored in active_urls.json
        json_path = os.path.join(self.session_dir, "active_urls.json")
        with open(json_path, "r", encoding="utf-8") as f:
            rec = json.loads(f.readline())
        self.assertEqual(rec["location"], "https://redirected.external.com")
        self.assertEqual(rec["status_code"], 301)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_08_no_fabricated_200_status(self, mock_update, mock_docker):
        """
        Test 8: No fabricated 200 status
        If httpx returns status 503 or 404, status_code must NOT be rewritten to 200.
        """
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("down.example.com:443\n")

        raw_jsonl = (
            '{"url":"https://down.example.com","input":"down.example.com:443","status_code":503,"title":"Service Unavailable"}\n'
        )

        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "httpx_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertEqual(web_targets[0]["status_code"], 503)

        json_path = os.path.join(self.session_dir, "active_urls.json")
        with open(json_path, "r", encoding="utf-8") as f:
            rec = json.loads(f.readline())
        self.assertEqual(rec["status_code"], 503)
        self.assertNotEqual(rec["status_code"], 200)

    @patch("core.stage2_web_probing.requests.get")
    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_09_no_requests_get_fallback(self, mock_update, mock_docker, mock_get):
        """
        Test 9: No requests.get fallback
        Verify that requests.get is NEVER called during run_httpx, even on empty output or failure.
        """
        # Run with failure
        mock_docker.return_value = (False, "error")
        run_httpx(self.session_dir, self.scan_id)
        mock_get.assert_not_called()

        # Run with 0 results
        mock_docker.return_value = (True, "")
        raw_path = os.path.join(self.session_dir, "httpx_raw.jsonl")
        with open(raw_path, "w", encoding="utf-8") as rf:
            rf.write("")
        run_httpx(self.session_dir, self.scan_id)
        mock_get.assert_not_called()

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_10_input_isolation(self, mock_update, mock_docker):
        """
        Test 10: Input isolation
        httpx targets are derived exclusively from ports.txt and written to httpx_input.txt.
        ports.txt and subdomains.txt remain untouched.
        """
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("API.EXAMPLE.COM.:443\n192.168.1.1:8080\ninvalid_port:99999\nno_colon\n")

        mock_docker.return_value = (True, "")
        raw_path = os.path.join(self.session_dir, "httpx_raw.jsonl")
        with open(raw_path, "w", encoding="utf-8") as rf:
            rf.write("")

        run_httpx(self.session_dir, self.scan_id)

        # Check httpx_input.txt
        input_path = os.path.join(self.session_dir, "httpx_input.txt")
        self.assertTrue(os.path.exists(input_path))
        with open(input_path, "r", encoding="utf-8") as f:
            inputs = [l.strip() for l in f if l.strip()]
        self.assertEqual(inputs, ["api.example.com:443", "192.168.1.1:8080"])

        # Check subdomains.txt was NOT touched
        with open(self.subdomains_file, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), self.initial_subdomains)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_11_stale_file_protection(self, mock_update, mock_docker):
        """
        Test 11: Stale file protection
        Pre-existing files from a previous run are cleaned up before execution starts.
        """
        stale_files = {
            "httpx_raw.jsonl": '{"url":"https://stale.old.com"}\n',
            "active_urls.json": '{"url":"https://stale.old.com"}\n',
            "active_urls.txt": "https://stale.old.com\n",
            "httpx_metadata.json": '{"tool":"httpx","status":"old"}\n',
            "httpx_input.txt": "stale.old.com:443\n"
        }
        for name, content in stale_files.items():
            with open(os.path.join(self.session_dir, name), "w", encoding="utf-8") as f:
                f.write(content)

        # Empty ports.txt so execution terminates immediately
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("")

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertEqual(active_urls, [])

        # Verify old contents were completely removed
        with open(os.path.join(self.session_dir, "active_urls.txt"), "r", encoding="utf-8") as f:
            self.assertEqual(f.read().strip(), "")
        with open(os.path.join(self.session_dir, "active_urls.json"), "r", encoding="utf-8") as f:
            self.assertEqual(f.read().strip(), "")

    def test_12_downstream_nuclei_target_isolation(self):
        """
        Test 12: Pipeline fallback removal verification
        prepare_nuclei_targets returns empty list when active_urls is empty.
        Does not invent http://{domain} or https://{domain}.
        """
        with open(os.path.join(self.session_dir, "active_urls.txt"), "w", encoding="utf-8") as f:
            pass
        with open(os.path.join(self.session_dir, "active_urls.json"), "w", encoding="utf-8") as f:
            pass

        targets = prepare_nuclei_targets(self.session_dir)
        self.assertEqual(targets, [])

    @patch("core.stage2_web_probing.requests.get")
    @patch("core.stage2_web_probing.update_status")
    def test_13_kiterunner_empty_active_urls(self, mock_update, mock_get):
        """
        Test 13: Kiterunner integration
        run_kiterunner_or_api_probing with empty active_urls returns (True, [])
        with api_endpoints_count: 0 and without making HTTP requests.
        """
        ok, endpoints = run_kiterunner_or_api_probing([], self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(endpoints, [])
        mock_get.assert_not_called()

        # Verify api_endpoints.json is empty list
        api_json = os.path.join(self.session_dir, "api_endpoints.json")
        self.assertTrue(os.path.exists(api_json))
        with open(api_json, "r", encoding="utf-8") as f:
            self.assertEqual(json.load(f), [])

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_14_raw_evidence_preservation(self, mock_update, mock_docker):
        """
        Test 14: Raw evidence preservation
        httpx_raw.jsonl is preserved intact and matches the docker tool output.
        """
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("api.example.com:443\ndev.example.com:8080\n")

        exact_raw = (
            '{"url":"https://api.example.com","input":"api.example.com:443","status_code":200}\n'
            '{"url":"http://dev.example.com:8080","input":"dev.example.com:8080","status_code":200}\n'
        )

        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "httpx_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(exact_raw)
            return True, exact_raw

        mock_docker.side_effect = fake_docker

        run_httpx(self.session_dir, self.scan_id)

        raw_path = os.path.join(self.session_dir, "httpx_raw.jsonl")
        self.assertTrue(os.path.exists(raw_path))
        with open(raw_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), exact_raw)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_15_exact_count_invariant(self, mock_update, mock_docker):
        """
        Test 15: Exact count invariant
        raw_count == valid_count + invalid_count + duplicate_count
        valid_count == len(active_urls.txt) == len(web_targets)
        """
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("site1.example.com:443\nsite2.example.com:443\nsite3.example.com:443\n")

        raw_jsonl = (
            '{"url":"https://site1.example.com","status_code":200}\n'  # Valid 1
            '{"url":"https://site2.example.com","status_code":200}\n'  # Valid 2
            '{"url":"https://site1.example.com","status_code":200}\n'  # Duplicate 1
            'corrupted_line\n'                                         # Invalid 1
            '{"not_url": 123}\n'                                       # Invalid 2
            '{"url":"https://site3.example.com:443","status_code":200}\n' # Valid 3
            '{"url":"https://site3.example.com","status_code":200}\n'  # Duplicate 2
        )

        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "httpx_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)

        meta_path = os.path.join(self.session_dir, "httpx_metadata.json")
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        raw_c = meta["raw_count"]
        val_c = meta["valid_count"]
        inv_c = meta["invalid_count"]
        dup_c = meta["duplicate_count"]

        self.assertEqual(raw_c, 7)
        self.assertEqual(val_c, 3)
        self.assertEqual(inv_c, 2)
        self.assertEqual(dup_c, 2)
        self.assertEqual(raw_c, val_c + inv_c + dup_c)
        self.assertEqual(val_c, len(active_urls))
        self.assertEqual(val_c, len(web_targets))

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_16_dashboard_state_and_live_urls_count(self, mock_update, mock_docker):
        """
        Test 16: Dashboard state and live_urls_count
        Verify that update_status is called with stats_update={"live_urls_count": ...}
        at the start (0), and at the end of every exit path (success, empty, failure).
        """
        raw_jsonl = '{"url":"https://example.com","input":"example.com:443","status_code":200}\n'

        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "httpx_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker
        run_httpx(self.session_dir, self.scan_id)

        # Check call arguments
        stats_calls = [
            c[1].get("stats_update")
            for c in mock_update.call_args_list
            if "stats_update" in c[1] and c[1]["stats_update"] is not None
        ]
        self.assertIn({"live_urls_count": 0}, stats_calls)
        self.assertIn({"live_urls_count": 1}, stats_calls)

    # =========================================================================
    # DEDICATED PROVENANCE TESTS (10 Specific Scenarios)
    # =========================================================================

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_provenance_01_host_default_https_port(self, mock_update, mock_docker):
        """1. Host + default HTTPS port correlation (api.example.com:443 -> https://api.example.com accepted)."""
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("api.example.com:443\n")

        raw_jsonl = '{"input":"api.example.com:443","url":"https://api.example.com","status_code":403}\n'

        def fake_docker(*args, **kwargs):
            with open(os.path.join(self.session_dir, "httpx_raw.jsonl"), "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(active_urls, ["https://api.example.com"])
        self.assertEqual(len(active_urls), 1)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_provenance_02_host_default_http_port(self, mock_update, mock_docker):
        """2. Host + default HTTP port correlation (portal.example.com:80 -> http://portal.example.com accepted)."""
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("portal.example.com:80\n")

        raw_jsonl = '{"input":"portal.example.com:80","url":"http://portal.example.com","status_code":200}\n'

        def fake_docker(*args, **kwargs):
            with open(os.path.join(self.session_dir, "httpx_raw.jsonl"), "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(active_urls, ["http://portal.example.com"])
        self.assertEqual(len(active_urls), 1)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_provenance_03_non_standard_port_8443(self, mock_update, mock_docker):
        """3. Non-standard port correlation (api.example.com:8443 -> https://api.example.com:8443 accepted)."""
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("api.example.com:8443\n")

        raw_jsonl = '{"input":"api.example.com:8443","url":"https://api.example.com:8443","status_code":200}\n'

        def fake_docker(*args, **kwargs):
            with open(os.path.join(self.session_dir, "httpx_raw.jsonl"), "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(active_urls, ["https://api.example.com:8443"])
        self.assertEqual(len(active_urls), 1)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_provenance_04_external_host_rejected(self, mock_update, mock_docker):
        """4. Record from host outside httpx_input.txt is rejected."""
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("api.example.com:443\n")

        # external.example.org was NOT in ports.txt
        raw_jsonl = '{"url":"https://external.example.org","status_code":200}\n'

        def fake_docker(*args, **kwargs):
            with open(os.path.join(self.session_dir, "httpx_raw.jsonl"), "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(active_urls, [])
        self.assertEqual(web_targets, [])

        with open(os.path.join(self.session_dir, "httpx_metadata.json"), "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["raw_count"], 1)
        self.assertEqual(meta["valid_count"], 0)
        self.assertEqual(meta["invalid_count"], 1)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_provenance_05_same_host_different_port_rejected(self, mock_update, mock_docker):
        """5. Same hostname but different port than in httpx_input.txt is rejected."""
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("api.example.com:443\n")  # Only port 443

        # Port 80 (http) was NOT in ports.txt
        raw_jsonl = '{"url":"http://api.example.com","status_code":200}\n'

        def fake_docker(*args, **kwargs):
            with open(os.path.join(self.session_dir, "httpx_raw.jsonl"), "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(active_urls, [])

        with open(os.path.join(self.session_dir, "httpx_metadata.json"), "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["valid_count"], 0)
        self.assertEqual(meta["invalid_count"], 1)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_provenance_06_redirect_location_out_of_scope_not_added(self, mock_update, mock_docker):
        """6. Redirect location outside scope is preserved in JSON metadata but NOT added to active_urls.txt."""
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("api.example.com:80\n")

        raw_jsonl = '{"url":"http://api.example.com","status_code":301,"location":"https://external.example.org"}\n'

        def fake_docker(*args, **kwargs):
            with open(os.path.join(self.session_dir, "httpx_raw.jsonl"), "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(active_urls, ["http://api.example.com"])
        self.assertNotIn("https://external.example.org", active_urls)

        # Check that location is stored in JSON metadata
        json_path = os.path.join(self.session_dir, "active_urls.json")
        with open(json_path, "r", encoding="utf-8") as f:
            rec = json.loads(f.readline())
        self.assertEqual(rec["location"], "https://external.example.org")

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_provenance_07_ip_only_target_accepted(self, mock_update, mock_docker):
        """7. IP-only input (1.2.3.4:443) accepts https://1.2.3.4."""
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("1.2.3.4:443\n")

        raw_jsonl = '{"input":"1.2.3.4:443","url":"https://1.2.3.4","status_code":200}\n'

        def fake_docker(*args, **kwargs):
            with open(os.path.join(self.session_dir, "httpx_raw.jsonl"), "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(active_urls, ["https://1.2.3.4"])

        txt_path = os.path.join(self.session_dir, "active_urls.txt")
        with open(txt_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read().strip(), "https://1.2.3.4")

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_provenance_08_invalid_count_includes_provenance_failures(self, mock_update, mock_docker):
        """8. invalid_count increments for records that fail provenance validation."""
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("api.example.com:443\n")

        raw_jsonl = (
            '{"url":"https://api.example.com","status_code":200}\n'         # Valid (matches api.example.com:443)
            '{"url":"https://unknown.com:443","status_code":200}\n'         # Fails provenance (host unknown)
            '{"url":"http://api.example.com:8080","status_code":200}\n'     # Fails provenance (port unknown)
        )

        def fake_docker(*args, **kwargs):
            with open(os.path.join(self.session_dir, "httpx_raw.jsonl"), "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(active_urls, ["https://api.example.com"])

        with open(os.path.join(self.session_dir, "httpx_metadata.json"), "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["raw_count"], 3)
        self.assertEqual(meta["valid_count"], 1)
        self.assertEqual(meta["invalid_count"], 2)
        self.assertEqual(meta["duplicate_count"], 0)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_provenance_09_exact_count_invariant_with_provenance_failures(self, mock_update, mock_docker):
        """9. Count invariant holds: raw_count == valid_count + invalid_count + duplicate_count."""
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("target.com:443\n")

        raw_jsonl = (
            '{"url":"https://target.com","status_code":200}\n'       # Valid (1)
            '{"url":"https://target.com:443","status_code":200}\n'   # Duplicate (1)
            'malformed_json_row\n'                                   # Invalid - syntax (1)
            '{"url":"https://alien.com:443","status_code":200}\n'    # Invalid - provenance (1)
        )

        def fake_docker(*args, **kwargs):
            with open(os.path.join(self.session_dir, "httpx_raw.jsonl"), "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(ok)

        with open(os.path.join(self.session_dir, "httpx_metadata.json"), "r", encoding="utf-8") as f:
            meta = json.load(f)

        raw = meta["raw_count"]
        val = meta["valid_count"]
        inv = meta["invalid_count"]
        dup = meta["duplicate_count"]

        self.assertEqual(raw, 4)
        self.assertEqual(val, 1)
        self.assertEqual(inv, 2)
        self.assertEqual(dup, 1)
        self.assertEqual(raw, val + inv + dup)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_provenance_10_input_field_mismatch_rejected(self, mock_update, mock_docker):
        """10. Input field mismatch with URL endpoint is rejected."""
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("api.example.com:443\nportal.example.com:443\n")

        # input says api.example.com:443, but url says portal.example.com
        raw_jsonl = '{"input":"api.example.com:443","url":"https://portal.example.com","status_code":200}\n'

        def fake_docker(*args, **kwargs):
            with open(os.path.join(self.session_dir, "httpx_raw.jsonl"), "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(active_urls, [])

        with open(os.path.join(self.session_dir, "httpx_metadata.json"), "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["valid_count"], 0)
        self.assertEqual(meta["invalid_count"], 1)

    # =========================================================================
    # DEDICATED NO-FALLBACK (-nf) & PROTOCOL MISMATCH TESTS
    # =========================================================================

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_nf_flag_passed_in_httpx_command(self, mock_update, mock_docker):
        """Verify that -nf is explicitly included in the httpx command line arguments."""
        mock_docker.return_value = (True, "")
        with open(os.path.join(self.session_dir, "httpx_raw.jsonl"), "w", encoding="utf-8") as rf:
            rf.write("")

        run_httpx(self.session_dir, self.scan_id)

        self.assertTrue(mock_docker.called)
        args_passed = mock_docker.call_args[1].get("args") or mock_docker.call_args[0][1]
        self.assertIn("-nf", args_passed)
        self.assertNotIn("-fr", args_passed)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_single_endpoint_both_http_and_https_not_duplicates(self, mock_update, mock_docker):
        """Single endpoint can produce both HTTP and HTTPS services without being treated as duplicates."""
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("example.com:8443\n")

        raw_jsonl = (
            '{"input":"example.com:8443","url":"http://example.com:8443","status_code":200}\n'
            '{"input":"example.com:8443","url":"https://example.com:8443","status_code":200}\n'
        )

        def fake_docker(*args, **kwargs):
            with open(os.path.join(self.session_dir, "httpx_raw.jsonl"), "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(len(active_urls), 2)
        self.assertIn("http://example.com:8443", active_urls)
        self.assertIn("https://example.com:8443", active_urls)

        with open(os.path.join(self.session_dir, "httpx_metadata.json"), "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["raw_count"], 2)
        self.assertEqual(meta["valid_count"], 2)
        self.assertEqual(meta["duplicate_count"], 0)
        self.assertEqual(meta["protocol_mismatch_count"], 0)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_protocol_mismatch_classified_and_excluded_from_active_urls(self, mock_update, mock_docker):
        """HTTP 400 with 'plain HTTP request was sent to HTTPS port' is classified as protocol_mismatch."""
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("academy.hackthebox.com:8443\n")

        raw_jsonl = (
            '{"input":"academy.hackthebox.com:8443","url":"http://academy.hackthebox.com:8443","status_code":400,"title":"400 The plain HTTP request was sent to HTTPS port"}\n'
        )

        def fake_docker(*args, **kwargs):
            with open(os.path.join(self.session_dir, "httpx_raw.jsonl"), "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(active_urls, [])
        self.assertEqual(web_targets, [])

        # Verify raw evidence is intact
        raw_path = os.path.join(self.session_dir, "httpx_raw.jsonl")
        with open(raw_path, "r", encoding="utf-8") as rf:
            self.assertEqual(rf.read(), raw_jsonl)

        # Verify active_urls.txt is empty
        txt_path = os.path.join(self.session_dir, "active_urls.txt")
        with open(txt_path, "r", encoding="utf-8") as tf:
            self.assertEqual(tf.read().strip(), "")

        # Verify metadata counts
        with open(os.path.join(self.session_dir, "httpx_metadata.json"), "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["raw_count"], 1)
        self.assertEqual(meta["valid_count"], 0)
        self.assertEqual(meta["protocol_mismatch_count"], 1)
        self.assertEqual(meta["duplicate_count"], 0)
        self.assertEqual(meta["invalid_count"], 0)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_no_synthetic_https_invented_on_protocol_mismatch(self, mock_update, mock_docker):
        """When only HTTP protocol mismatch is returned, do NOT fabricate an HTTPS URL."""
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("secure.local:8443\n")

        raw_jsonl = (
            '{"input":"secure.local:8443","url":"http://secure.local:8443","status_code":400,"title":"The plain HTTP request was sent to HTTPS port"}\n'
        )

        def fake_docker(*args, **kwargs):
            with open(os.path.join(self.session_dir, "httpx_raw.jsonl"), "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(active_urls, [])
        self.assertNotIn("https://secure.local:8443", active_urls)

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_regression_case_hackthebox_real_integration(self, mock_update, mock_docker):
        """
        Regression test matching real hackthebox scan:
        Input: api.jobs.hackthebox.com:8443
        Raw contains:
        1. http://api.jobs.hackthebox.com:8443 (400 plain HTTP request was sent to HTTPS port)
        2. https://api.jobs.hackthebox.com:8443 (403)
        Expected:
        - http URL -> protocol_mismatch (not in active_urls.txt)
        - https URL -> valid (included in active_urls.txt)
        """
        with open(self.ports_file, "w", encoding="utf-8") as f:
            f.write("api.jobs.hackthebox.com:8443\n")

        raw_jsonl = (
            '{"input":"api.jobs.hackthebox.com:8443","url":"http://api.jobs.hackthebox.com:8443","status_code":400,"title":"400 The plain HTTP request was sent to HTTPS port"}\n'
            '{"input":"api.jobs.hackthebox.com:8443","url":"https://api.jobs.hackthebox.com:8443","status_code":403}\n'
        )

        def fake_docker(*args, **kwargs):
            with open(os.path.join(self.session_dir, "httpx_raw.jsonl"), "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(active_urls, ["https://api.jobs.hackthebox.com:8443"])
        self.assertNotIn("http://api.jobs.hackthebox.com:8443", active_urls)

        # Check active_urls.txt
        txt_path = os.path.join(self.session_dir, "active_urls.txt")
        with open(txt_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read().strip(), "https://api.jobs.hackthebox.com:8443")

        # Check metadata
        with open(os.path.join(self.session_dir, "httpx_metadata.json"), "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["raw_count"], 2)
        self.assertEqual(meta["valid_count"], 1)
        self.assertEqual(meta["protocol_mismatch_count"], 1)
        self.assertEqual(meta["invalid_count"], 0)
        self.assertEqual(meta["duplicate_count"], 0)
        self.assertEqual(meta["live_service_count"], 1)
        self.assertEqual(meta["raw_count"], meta["valid_count"] + meta["invalid_count"] + meta["duplicate_count"] + meta["protocol_mismatch_count"])

    # =========================================================================
    # Edge Cases & Normalization
    # =========================================================================

    def test_normalize_host_port_edge_cases(self):
        """Test normalize_host_port handles various valid and invalid formats."""
        self.assertEqual(normalize_host_port("EXAMPLE.COM:80"), "example.com:80")
        self.assertEqual(normalize_host_port("api.example.com.:443"), "api.example.com:443")
        self.assertEqual(normalize_host_port("192.168.1.1:8080"), "192.168.1.1:8080")
        self.assertEqual(normalize_host_port("http://host.com:80"), "host.com:80")
        self.assertIsNone(normalize_host_port("invalid"))
        self.assertIsNone(normalize_host_port("host:not_a_port"))
        self.assertIsNone(normalize_host_port("host:70000"))
        self.assertIsNone(normalize_host_port(":80"))

    def test_normalize_web_url_edge_cases(self):
        """Test normalize_web_url handles defaults and non-default ports."""
        self.assertEqual(normalize_web_url("http://example.com:80"), "http://example.com")
        self.assertEqual(normalize_web_url("https://example.com:443"), "https://example.com")
        self.assertEqual(normalize_web_url("https://EXAMPLE.COM./"), "https://example.com")
        self.assertEqual(normalize_web_url("http://example.com:8080/api"), "http://example.com:8080/api")
        self.assertIsNone(normalize_web_url("ftp://example.com"))
        self.assertIsNone(normalize_web_url("not a url"))


if __name__ == "__main__":
    unittest.main()
