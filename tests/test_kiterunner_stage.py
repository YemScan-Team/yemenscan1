import os
import sys
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
import os
import sys
import json
import shutil
import tempfile
import unittest
import hashlib
from unittest.mock import patch, MagicMock

from core.stage2_web_probing import (
    run_kiterunner_or_api_probing,
    normalize_kiterunner_input,
    normalize_endpoint_url,
    KITERUNNER_DOCKER_IMAGE,
    KITERUNNER_UPSTREAM_VERSION,
    KITERUNNER_UPSTREAM_COMMIT,
    KITERUNNER_BUILD_VARIANT,
    KITERUNNER_PATCHES,
    KITERUNNER_WORDLIST_NAME,
    KITERUNNER_WORDLIST_SHA256,
)


class TestKiterunnerStage(unittest.TestCase):
    """
    Comprehensive test suite for the Kiterunner API route discovery stage.
    Covers single and multi-response processing, strict provenance, deduplication,
    metadata invariants, and patch verification.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.scan_id = "test_scan_kr_123"

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_active_urls_is_sole_input(self):
        """1. active_urls is the sole source, normalized and written to kiterunner_input.txt."""
        active = ["https://api.example.com", "http://portal.example.com:8080/"]
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, "")
            run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)

            inp_file = os.path.join(self.test_dir, "kiterunner_input.txt")
            self.assertTrue(os.path.exists(inp_file))
            with open(inp_file, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip()]
            self.assertEqual(lines, ["https://api.example.com", "http://portal.example.com:8080"])

    def test_02_empty_input_does_not_run_kiterunner(self):
        """2. Empty input does not run Kiterunner (run_docker_tool never called)."""
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            ok, endpoints = run_kiterunner_or_api_probing([], self.test_dir, self.scan_id)
            self.assertTrue(ok)
            self.assertEqual(endpoints, [])
            mock_dock.assert_not_called()

            meta_file = os.path.join(self.test_dir, "kiterunner_metadata.json")
            self.assertTrue(os.path.exists(meta_file))
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            self.assertEqual(meta["input_count"], 0)
            self.assertEqual(meta["raw_event_count"], 0)
            self.assertEqual(meta["candidate_count"], 0)
            self.assertEqual(meta["status"], "completed")

    def test_03_no_root_url_fallback(self):
        """3. No root URL guessing or fallback when input is empty."""
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            with patch("core.stage2_web_probing.get_status") as mock_stat:
                mock_stat.return_value = {"target_domain": "example.com"}
                ok, endpoints = run_kiterunner_or_api_probing([], self.test_dir, self.scan_id)
                self.assertEqual(endpoints, [])
                txt_file = os.path.join(self.test_dir, "api_endpoints.txt")
                self.assertTrue(os.path.exists(txt_file))
                with open(txt_file, "r", encoding="utf-8") as f:
                    self.assertEqual(f.read().strip(), "")

    def test_04_no_requests_get_probing(self):
        """4. Verify requests.get is not used in stage2_web_probing for API discovery."""
        stage2_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "core", "stage2_web_probing.py"))
        with open(stage2_path, "r", encoding="utf-8") as f:
            code = f.read()
        self.assertNotIn("_probe_single_endpoint", code)
        # Note: requests may be imported at module level for compatibility, but never called for probing
        self.assertNotIn("requests.get", code)

    def test_05_no_common_api_paths_fallback(self):
        """5. Verify static COMMON_API_PATHS list is completely removed."""
        stage2_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "core", "stage2_web_probing.py"))
        with open(stage2_path, "r", encoding="utf-8") as f:
            code = f.read()
        self.assertNotIn("COMMON_API_PATHS", code)

    def test_06_no_active_urls_first_six_cap(self):
        """6. No silent sample_hosts[:6] cap: all active URLs must be passed to input."""
        active = [f"https://sub{i}.example.com" for i in range(12)]
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, "")
            run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            inp_file = os.path.join(self.test_dir, "kiterunner_input.txt")
            with open(inp_file, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip()]
            self.assertEqual(len(lines), 12)

    def test_07_docker_executes_kr(self):
        """7. Docker execution uses pinned yemscan/kiterunner:v1.0.2-yemscan1 and calls 'scan'."""
        active = ["https://api.example.com"]
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, "")
            run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            mock_dock.assert_called_once()
            call_kwargs = mock_dock.call_args[1]
            self.assertEqual(call_kwargs["image"], "yemscan/kiterunner:v1.0.2-yemscan1")
            self.assertEqual(call_kwargs["args"][0], "scan")
            self.assertEqual(call_kwargs["args"][1], "/data/kiterunner_input.txt")

    def test_08_version_and_metadata_distinguishes_variant(self):
        """8. Engine variant is distinctly tracked (v1.0.2-yemscan1 with e7a7fa6 upstream)."""
        self.assertEqual(KITERUNNER_UPSTREAM_VERSION, "v1.0.2")
        self.assertEqual(KITERUNNER_UPSTREAM_COMMIT, "e7a7fa6")
        self.assertEqual(KITERUNNER_BUILD_VARIANT, "yemscan1")
        self.assertEqual(KITERUNNER_DOCKER_IMAGE, "yemscan/kiterunner:v1.0.2-yemscan1")
        self.assertIn("remove-default-x-forwarded-for", KITERUNNER_PATCHES)

    def test_09_wordlist_bundled_and_verified(self):
        """9. Wordlist routes-small.kite exists and matches expected SHA256 checksum."""
        self.assertEqual(KITERUNNER_WORDLIST_NAME, "routes-small.kite")
        self.assertEqual(KITERUNNER_WORDLIST_SHA256, "2b1bcac8666580c15cc763dd41a2360553439b729b6234679f5f05bdd10cb514")
        wordlist_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "routes-small.kite"))
        self.assertTrue(os.path.exists(wordlist_path), "routes-small.kite must be present in workspace")
        with open(wordlist_path, "rb") as f:
            computed_sha = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(computed_sha, KITERUNNER_WORDLIST_SHA256)

    def test_10_default_x_forwarded_for_eliminated(self):
        """10. Verify patched source code does not include default X-Forwarded-For: 127.0.0.1."""
        scan_go = os.path.abspath(os.path.join(os.path.dirname(__file__), "kiterunner-src", "kiterunner-1.0.2", "cmd", "kiterunner", "cmd", "scan.go"))
        if os.path.exists(scan_go):
            with open(scan_go, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn('[]string{"x-forwarded-for: 127.0.0.1"}', content)
            self.assertIn('&headers, "header", "H", []string{}', content)

    def test_11_wildcard_detection_enabled(self):
        """11. Wildcard detection is enabled with --quarantine-threshold 10 and -d 1."""
        active = ["https://api.example.com"]
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, "")
            run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            args = mock_dock.call_args[1]["args"]
            self.assertIn("--quarantine-threshold", args)
            idx = args.index("--quarantine-threshold")
            self.assertEqual(args[idx + 1], "10")
            self.assertIn("-d", args)
            d_idx = args.index("-d")
            self.assertEqual(args[d_idx + 1], "1")

    def test_12_max_redirects_zero(self):
        """12. Execution uses --max-redirects 0 to prevent expanding outside target scope."""
        active = ["https://api.example.com"]
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, "")
            run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            args = mock_dock.call_args[1]["args"]
            self.assertIn("--max-redirects", args)
            idx = args.index("--max-redirects")
            self.assertEqual(args[idx + 1], "0")

    def test_13_tool_failure_handling(self):
        """13. Tool failure -> status failed + zero candidates + error in stderr.log."""
        active = ["https://api.example.com"]
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (False, "Fatal error: Docker container died")
            ok, endpoints = run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            self.assertFalse(ok)
            self.assertEqual(endpoints, [])

            stderr_file = os.path.join(self.test_dir, "kiterunner_stderr.log")
            self.assertTrue(os.path.exists(stderr_file))
            with open(stderr_file, "r", encoding="utf-8") as f:
                self.assertIn("Fatal error", f.read())

            meta_file = os.path.join(self.test_dir, "kiterunner_metadata.json")
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            self.assertEqual(meta["status"], "failed")
            self.assertEqual(meta["candidate_count"], 0)

    def test_14_zero_results_handling(self):
        """14. Zero results -> status empty/completed without synthesizing any API routes."""
        active = ["https://api.example.com"]
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, "")
            ok, endpoints = run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            self.assertTrue(ok)
            self.assertEqual(endpoints, [])

            meta_file = os.path.join(self.test_dir, "kiterunner_metadata.json")
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            self.assertEqual(meta["status"], "completed")
            self.assertEqual(meta["candidate_count"], 0)
            self.assertEqual(meta["valid_count"], 0)

    def test_15_malformed_raw_output_increments_invalid_event_count(self):
        """15. Malformed raw output records increment invalid_event_count; invariant holds."""
        active = ["https://api.example.com"]
        raw_output = "\n".join([
            '{"level":"info","method":"GET","target":"https://api.example.com","path":"/api/v1/users","responses":[{"uri":"https://api.example.com/api/v1/users","sc":200,"len":100}]}',
            'NOT_VALID_JSON',
            '{"missing_method": true}',
            '{"level":"info","method":"GET","target":"https://api.example.com","path":"/api/v1/badsc","responses":[{"uri":"https://api.example.com/api/v1/badsc","sc":"invalid_code"}]}'
        ])
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, raw_output)
            ok, endpoints = run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            self.assertTrue(ok)
            self.assertEqual(len(endpoints), 1)

            meta_file = os.path.join(self.test_dir, "kiterunner_metadata.json")
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            self.assertEqual(meta["raw_event_count"], 4)
            self.assertEqual(meta["parsed_event_count"], 2)
            self.assertEqual(meta["invalid_event_count"], 2)
            self.assertEqual(meta["raw_event_count"], meta["parsed_event_count"] + meta["invalid_event_count"])
            self.assertEqual(meta["response_record_count"], 2)
            self.assertEqual(meta["valid_count"], 1)
            self.assertEqual(meta["invalid_response_count"], 1)
            self.assertEqual(meta["duplicate_count"], 0)
            self.assertEqual(meta["response_record_count"], meta["valid_count"] + meta["invalid_response_count"] + meta["duplicate_count"])

    def test_16_duplicate_method_and_url_increments_duplicate_count(self):
        """16. Duplicate (method, normalized_url) increments duplicate_count; invariant holds."""
        active = ["https://api.example.com"]
        raw_output = "\n".join([
            '{"level":"info","method":"GET","target":"https://api.example.com","path":"/api/v1/users","responses":[{"uri":"https://api.example.com/api/v1/users","sc":200,"len":100}]}',
            '{"level":"info","method":"GET","target":"https://api.example.com","path":"/api/v1/users","responses":[{"uri":"https://api.example.com/api/v1/users","sc":200,"len":100}]}'
        ])
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, raw_output)
            ok, endpoints = run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            self.assertTrue(ok)
            self.assertEqual(len(endpoints), 1)

            meta_file = os.path.join(self.test_dir, "kiterunner_metadata.json")
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            self.assertEqual(meta["raw_event_count"], 2)
            self.assertEqual(meta["response_record_count"], 2)
            self.assertEqual(meta["valid_count"], 1)
            self.assertEqual(meta["duplicate_count"], 1)
            self.assertEqual(meta["invalid_response_count"], 0)

    def test_17_different_methods_same_url_not_duplicate(self):
        """17. GET and POST to the same URL are distinct routes and not duplicates."""
        active = ["https://api.example.com"]
        raw_output = "\n".join([
            '{"level":"info","method":"GET","target":"https://api.example.com","path":"/api/v1/users","responses":[{"uri":"https://api.example.com/api/v1/users","sc":200,"len":100}]}',
            '{"level":"info","method":"POST","target":"https://api.example.com","path":"/api/v1/users","responses":[{"uri":"https://api.example.com/api/v1/users","sc":201,"len":50}]}'
        ])
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, raw_output)
            ok, endpoints = run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            self.assertTrue(ok)
            self.assertEqual(len(endpoints), 2)
            methods = [ep["method"] for ep in endpoints]
            self.assertIn("GET", methods)
            self.assertIn("POST", methods)

    def test_18_provenance_validation_rejects_foreign_origin(self):
        """18. Result outside input origin is rejected (provenance validation)."""
        active = ["https://api.example.com"]
        raw_output = "\n".join([
            '{"level":"info","method":"GET","target":"https://api.example.com","path":"/api/v1/users","responses":[{"uri":"https://api.example.com/api/v1/users","sc":200,"len":100}]}',
            '{"level":"info","method":"GET","target":"https://evil.external.com","path":"/api/v1/users","responses":[{"uri":"https://evil.external.com/api/v1/users","sc":200,"len":100}]}'
        ])
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, raw_output)
            ok, endpoints = run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            self.assertTrue(ok)
            self.assertEqual(len(endpoints), 1)
            self.assertEqual(endpoints[0]["origin"], "https://api.example.com")

            meta_file = os.path.join(self.test_dir, "kiterunner_metadata.json")
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            self.assertEqual(meta["invalid_response_count"], 1)

    def test_19_external_redirect_not_adopted(self):
        """19. External redirect target is not adopted as a target URL."""
        active = ["https://api.example.com"]
        raw_output = json.dumps({
            "level": "info",
            "method": "GET",
            "target": "https://api.example.com",
            "path": "/login",
            "responses": [
                {"uri": "https://api.example.com/login", "sc": 302, "len": 0},
                {"uri": "https://external-auth.provider.com/oauth", "sc": 200, "len": 500}
            ]
        })
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, raw_output)
            ok, endpoints = run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            self.assertTrue(ok)
            self.assertEqual(len(endpoints), 1)
            self.assertEqual(endpoints[0]["url"], "https://api.example.com/login")
            self.assertEqual(endpoints[0]["origin"], "https://api.example.com")

    def test_20_raw_evidence_not_overwritten(self):
        """20. Raw evidence in kiterunner_raw.jsonl is preserved and not overwritten with parsed objects."""
        active = ["https://api.example.com"]
        original_raw = '{"level":"info","method":"GET","target":"https://api.example.com","path":"/test","responses":[{"uri":"https://api.example.com/test","sc":200,"len":10}]}'
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, original_raw)
            run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)

            raw_file = os.path.join(self.test_dir, "kiterunner_raw.jsonl")
            self.assertTrue(os.path.exists(raw_file))
            with open(raw_file, "r", encoding="utf-8") as f:
                saved_content = f.read()
            self.assertEqual(saved_content, original_raw)

    def test_21_api_endpoints_txt_content(self):
        """21. api_endpoints.txt contains only verified candidate URLs discovered by Kiterunner."""
        active = ["https://api.example.com"]
        raw_output = "\n".join([
            '{"level":"info","method":"GET","target":"https://api.example.com","path":"/api/users","responses":[{"uri":"https://api.example.com/api/users","sc":200,"len":100}]}',
            '{"level":"info","method":"POST","target":"https://api.example.com","path":"/api/tokens","responses":[{"uri":"https://api.example.com/api/tokens","sc":201,"len":20}]}'
        ])
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, raw_output)
            run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)

            txt_file = os.path.join(self.test_dir, "api_endpoints.txt")
            with open(txt_file, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip()]
            self.assertEqual(set(lines), {"https://api.example.com/api/users", "https://api.example.com/api/tokens"})

    def test_22_dashboard_status_transitions(self):
        """22. Dashboard status correctly updates for success, empty, and failed."""
        active = ["https://api.example.com"]
        with patch("core.stage2_web_probing.update_status") as mock_stat:
            with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
                # 1. Success case
                mock_dock.return_value = (True, '{"level":"info","method":"GET","target":"https://api.example.com","path":"/api","responses":[{"uri":"https://api.example.com/api","sc":200,"len":10}]}')
                run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
                last_call_kwargs = mock_stat.call_args[1]
                self.assertEqual(last_call_kwargs["tool_status"], {"kiterunner": "success"})
                self.assertEqual(last_call_kwargs["stats_update"], {"api_endpoints_count": 1})

                # 2. Empty case
                mock_dock.return_value = (True, '')
                run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
                last_call_kwargs = mock_stat.call_args[1]
                self.assertEqual(last_call_kwargs["tool_status"], {"kiterunner": "empty"})
                self.assertEqual(last_call_kwargs["stats_update"], {"api_endpoints_count": 0})

                # 3. Failed case
                mock_dock.return_value = (False, 'error')
                run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
                last_call_kwargs = mock_stat.call_args[1]
                self.assertEqual(last_call_kwargs["tool_status"], {"kiterunner": "failed"})
                self.assertEqual(last_call_kwargs["stats_update"], {"api_endpoints_count": 0})

    def test_23_stale_files_cleaned(self):
        """23. Stale files from previous scans are wiped before execution."""
        old_raw = os.path.join(self.test_dir, "kiterunner_raw.jsonl")
        old_txt = os.path.join(self.test_dir, "api_endpoints.txt")
        with open(old_raw, "w") as f:
            f.write("STALE_RAW_DATA")
        with open(old_txt, "w") as f:
            f.write("https://stale.example.com/api")

        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, "")
            run_kiterunner_or_api_probing(["https://api.example.com"], self.test_dir, self.scan_id)
            with open(old_txt, "r", encoding="utf-8") as f:
                self.assertEqual(f.read().strip(), "")
            with open(old_raw, "r", encoding="utf-8") as f:
                self.assertEqual(f.read().strip(), "")

    def test_24_metadata_invariants(self):
        """24. Metadata invariants hold across mixed events and responses."""
        active = ["https://api.example.com"]
        raw_output = "\n".join([
            '{"level":"info","method":"GET","target":"https://api.example.com","path":"/route1","responses":[{"uri":"https://api.example.com/route1","sc":200,"len":100}]}',
            '{"level":"info","method":"GET","target":"https://api.example.com","path":"/route1","responses":[{"uri":"https://api.example.com/route1","sc":200,"len":100}]}',
            'MALFORMED_LINE',
            '{"level":"info","method":"POST","target":"https://api.example.com","path":"/route2","responses":[{"uri":"https://api.example.com/route2","sc":201,"len":50}]}'
        ])
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, raw_output)
            ok, endpoints = run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            self.assertTrue(ok)

            meta_file = os.path.join(self.test_dir, "kiterunner_metadata.json")
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)

            self.assertEqual(meta["raw_event_count"], 4)
            self.assertEqual(meta["parsed_event_count"], 3)
            self.assertEqual(meta["invalid_event_count"], 1)
            self.assertEqual(meta["raw_event_count"], meta["parsed_event_count"] + meta["invalid_event_count"])

            self.assertEqual(meta["response_record_count"], 3)
            self.assertEqual(meta["valid_count"], 2)
            self.assertEqual(meta["duplicate_count"], 1)
            self.assertEqual(meta["invalid_response_count"], 0)
            self.assertEqual(meta["response_record_count"], meta["valid_count"] + meta["invalid_response_count"] + meta["duplicate_count"])
            self.assertEqual(meta["candidate_count"], len(endpoints))

    def test_25_multi_response_all_valid(self):
        """25. Event with multiple valid responses yields multiple valid endpoints."""
        active = ["https://api.example.com"]
        raw_output = json.dumps({
            "method": "GET",
            "responses": [
                {"uri": "https://api.example.com/a", "sc": 200, "len": 10},
                {"uri": "https://api.example.com/b", "sc": 401, "len": 20}
            ]
        })
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, raw_output)
            ok, endpoints = run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            self.assertTrue(ok)
            self.assertEqual(len(endpoints), 2)
            urls = {ep["url"] for ep in endpoints}
            self.assertEqual(urls, {"https://api.example.com/a", "https://api.example.com/b"})

            meta_file = os.path.join(self.test_dir, "kiterunner_metadata.json")
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            self.assertEqual(meta["raw_event_count"], 1)
            self.assertEqual(meta["response_record_count"], 2)
            self.assertEqual(meta["valid_count"], 2)
            self.assertEqual(meta["invalid_response_count"], 0)

    def test_26_multi_response_one_valid_one_malformed(self):
        """26. First response valid, second malformed -> 1 valid, 1 invalid_response."""
        active = ["https://api.example.com"]
        raw_output = json.dumps({
            "method": "GET",
            "responses": [
                {"uri": "https://api.example.com/a", "sc": 200, "len": 10},
                {"uri": "not_a_valid_url", "sc": "bad_code", "len": 0}
            ]
        })
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, raw_output)
            ok, endpoints = run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            self.assertTrue(ok)
            self.assertEqual(len(endpoints), 1)
            self.assertEqual(endpoints[0]["url"], "https://api.example.com/a")

            meta_file = os.path.join(self.test_dir, "kiterunner_metadata.json")
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            self.assertEqual(meta["raw_event_count"], 1)
            self.assertEqual(meta["response_record_count"], 2)
            self.assertEqual(meta["valid_count"], 1)
            self.assertEqual(meta["invalid_response_count"], 1)

    def test_27_multi_response_one_duplicate_one_new(self):
        """27. First response duplicate, second response new -> 1 duplicate, 1 valid."""
        active = ["https://api.example.com"]
        raw_output = "\n".join([
            json.dumps({"method": "GET", "responses": [{"uri": "https://api.example.com/a", "sc": 200, "len": 10}]}),
            json.dumps({
                "method": "GET",
                "responses": [
                    {"uri": "https://api.example.com/a", "sc": 200, "len": 10},
                    {"uri": "https://api.example.com/b", "sc": 200, "len": 10}
                ]
            })
        ])
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, raw_output)
            ok, endpoints = run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            self.assertTrue(ok)
            self.assertEqual(len(endpoints), 2)

            meta_file = os.path.join(self.test_dir, "kiterunner_metadata.json")
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            self.assertEqual(meta["raw_event_count"], 2)
            self.assertEqual(meta["response_record_count"], 3)
            self.assertEqual(meta["valid_count"], 2)
            self.assertEqual(meta["duplicate_count"], 1)

    def test_28_multi_response_outside_origin_rejected_without_rejecting_valid(self):
        """28. Response outside provenance origin is rejected without rejecting valid sibling."""
        active = ["https://api.example.com"]
        raw_output = json.dumps({
            "method": "GET",
            "responses": [
                {"uri": "https://api.example.com/valid", "sc": 200, "len": 10},
                {"uri": "https://unauthorized.external.com/foreign", "sc": 200, "len": 10}
            ]
        })
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, raw_output)
            ok, endpoints = run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            self.assertTrue(ok)
            self.assertEqual(len(endpoints), 1)
            self.assertEqual(endpoints[0]["url"], "https://api.example.com/valid")

            meta_file = os.path.join(self.test_dir, "kiterunner_metadata.json")
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            self.assertEqual(meta["valid_count"], 1)
            self.assertEqual(meta["invalid_response_count"], 1)

    def test_29_patch_file_exists_and_valid(self):
        """29. Verify patch file exists and cleanly documents the X-Forwarded-For removal."""
        patch_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "patches", "kiterunner-v1.0.2-remove-xff.patch"))
        self.assertTrue(os.path.exists(patch_file), "Patch file must exist in patches/")
        with open(patch_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("x-forwarded-for: 127.0.0.1", content)
        self.assertIn("[]string{}", content)

    def test_30_content_length_zero_preserved(self):
        """30. Verify content_length=0 is preserved and not coerced to None/null or lost."""
        active = ["https://api.example.com"]
        raw_output = json.dumps({
            "method": "GET",
            "responses": [
                {
                    "uri": "https://api.example.com/empty",
                    "sc": 204,
                    "len": 0
                }
            ]
        })
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, raw_output)
            ok, endpoints = run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            self.assertTrue(ok)
            self.assertEqual(len(endpoints), 1)
            self.assertEqual(endpoints[0]["url"], "https://api.example.com/empty")
            self.assertEqual(endpoints[0]["status_code"], 204)
            self.assertEqual(endpoints[0]["content_length"], 0)

            # Check JSON serialization in api_endpoints.json
            endpoints_json_file = os.path.join(self.test_dir, "api_endpoints.json")
            with open(endpoints_json_file, "r", encoding="utf-8") as f:
                saved_endpoints = json.load(f)
            self.assertEqual(len(saved_endpoints), 1)
            self.assertEqual(saved_endpoints[0]["status_code"], 204)
            self.assertEqual(saved_endpoints[0]["content_length"], 0)

    def test_31_invalid_negative_or_non_numeric_content_length_becomes_none(self):
        """31. Verify negative (len: -1) or non-numeric len becomes None/null without invalidating the endpoint."""
        active = ["https://api.example.com"]
        raw_lines = [
            json.dumps({
                "method": "GET",
                "responses": [
                    {
                        "uri": "https://api.example.com/negative",
                        "sc": 200,
                        "len": -1
                    }
                ]
            }),
            json.dumps({
                "method": "POST",
                "responses": [
                    {
                        "uri": "https://api.example.com/non_numeric",
                        "sc": 201,
                        "len": "not_an_int"
                    }
                ]
            })
        ]
        raw_output = "\n".join(raw_lines)
        with patch("core.stage2_web_probing.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, raw_output)
            ok, endpoints = run_kiterunner_or_api_probing(active, self.test_dir, self.scan_id)
            self.assertTrue(ok)
            self.assertEqual(len(endpoints), 2)

            self.assertEqual(endpoints[0]["url"], "https://api.example.com/negative")
            self.assertEqual(endpoints[0]["status_code"], 200)
            self.assertIsNone(endpoints[0]["content_length"])

            self.assertEqual(endpoints[1]["url"], "https://api.example.com/non_numeric")
            self.assertEqual(endpoints[1]["status_code"], 201)
            self.assertIsNone(endpoints[1]["content_length"])

            # Verify in JSON file that content_length is null
            endpoints_json_file = os.path.join(self.test_dir, "api_endpoints.json")
            with open(endpoints_json_file, "r", encoding="utf-8") as f:
                saved_endpoints = json.load(f)
            self.assertEqual(len(saved_endpoints), 2)
            self.assertIsNone(saved_endpoints[0]["content_length"])
            self.assertIsNone(saved_endpoints[1]["content_length"])

            # Invariants and metadata checks: endpoints are NOT invalidated
            meta_file = os.path.join(self.test_dir, "kiterunner_metadata.json")
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            self.assertEqual(meta["valid_count"], 2)
            self.assertEqual(meta["invalid_response_count"], 0)


if __name__ == "__main__":
    unittest.main()

