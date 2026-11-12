"""
Unit and integration tests for the Naabu stage in YemenScan.

Covers all acceptance criteria:
1. No forced open ports (80/443).
2. No native socket / TCP checks merged into Naabu results.
3. Provenance preserved: no arbitrary IP-to-host mapping dictionary.
4. Raw output preserved in naabu_raw.jsonl (JSON Lines).
5. Clean validated ports stored in ports.txt.
6. Execution metadata stored in naabu_metadata.json with exact counts.
7. Correct failure handling (status=failed, ports=[], open_ports_count=0).
8. Zero-results behavior (success=True, ports=[], open_ports_count=0).
9. File isolation: subdomains.txt is never touched by Naabu.
10. Input isolation: naabu_targets.txt is used as input without adding IPs.
11. Pinned Docker tag: projectdiscovery/naabu:v2.6.1.
12. Timeout >= 240 seconds.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
from unittest.mock import patch

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.stage1_discovery import run_naabu, NAABU_PORTS, SCANNED_PORTS


class TestNaabuStage(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ys_naabu_test_")
        self.scan_id = "test_naabu_session_001"
        self.session_dir = os.path.join(self.test_dir, self.scan_id)
        os.makedirs(self.session_dir, exist_ok=True)

        # Status file
        status_path = os.path.join(self.session_dir, "status.json")
        with open(status_path, "w", encoding="utf-8") as f:
            json.dump({
                "scan_id": self.scan_id,
                "target_domain": "example.com",
                "current_stage": "phase1_discovery",
                "progress_percentage": 20,
                "logs": [],
                "is_completed": False,
                "has_error": False,
                "error_message": None,
                "stats": {"open_ports_count": 0}
            }, f)

        # Subfinder subdomains file (must remain untouched!)
        self.subdomains_file = os.path.join(self.session_dir, "subdomains.txt")
        self.initial_subdomains = "api.example.com\nwww.example.com\n"
        with open(self.subdomains_file, "w", encoding="utf-8") as f:
            f.write(self.initial_subdomains)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_01_real_naabu_result(self, mock_update, mock_docker):
        """
        Test 1: Real Naabu result
        Raw: {"host":"api.example.com","ip":"1.2.3.4","port":443}
        Expected: api.example.com:443 in ports.txt
        """
        raw_jsonl = '{"host":"api.example.com","ip":"1.2.3.4","port":443}\n'
        
        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "naabu_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, ports = run_naabu(["example.com", "api.example.com"], self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertEqual(ports, ["api.example.com:443"])

        # Check ports.txt
        ports_path = os.path.join(self.session_dir, "ports.txt")
        self.assertTrue(os.path.exists(ports_path))
        with open(ports_path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertEqual(lines, ["api.example.com:443"])

        # Check metadata
        meta_path = os.path.join(self.session_dir, "naabu_metadata.json")
        self.assertTrue(os.path.exists(meta_path))
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["tool"], "naabu")
        self.assertEqual(meta["status"], "completed")
        self.assertEqual(meta["valid_count"], 1)
        self.assertEqual(meta["raw_count"], 1)
        self.assertEqual(meta["open_endpoint_count"], 1)
        self.assertEqual(meta["unique_port_count"], 1)

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_02_zero_results_behavior(self, mock_update, mock_docker):
        """
        Test 2: No results
        Naabu succeeds but raw output is empty.
        Expected: ports = [], open_ports_count = 0, no forced 80 or 443.
        """
        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "naabu_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write("")
            return True, ""

        mock_docker.side_effect = fake_docker

        ok, ports = run_naabu(["example.com"], self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertEqual(ports, [])

        ports_path = os.path.join(self.session_dir, "ports.txt")
        self.assertTrue(os.path.exists(ports_path))
        with open(ports_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read().strip(), "")

        meta_path = os.path.join(self.session_dir, "naabu_metadata.json")
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["status"], "completed")
        self.assertEqual(meta["valid_count"], 0)
        self.assertEqual(meta["open_endpoint_count"], 0)
        self.assertEqual(meta["unique_port_count"], 0)

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_03_tool_failure_handling(self, mock_update, mock_docker):
        """
        Test 3: Tool failure
        Simulation: run_docker_tool -> False
        Expected: status = failed, ports = [], no fallback results.
        """
        mock_docker.return_value = (False, "Process exited with code 1: network interface error")

        ok, ports = run_naabu(["example.com"], self.session_dir, self.scan_id)

        self.assertFalse(ok)
        self.assertEqual(ports, [])

        meta_path = os.path.join(self.session_dir, "naabu_metadata.json")
        self.assertTrue(os.path.exists(meta_path))
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["tool"], "naabu")
        self.assertEqual(meta["status"], "failed")
        self.assertEqual(meta["valid_count"], 0)
        self.assertIn("network interface error", meta["error"])

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_04_duplicate_handling(self, mock_update, mock_docker):
        """
        Test 4: Duplicate
        Raw contains the same Naabu result twice.
        Expected: valid_count = 1, duplicate_count = 1.
        """
        raw_jsonl = (
            '{"host":"api.example.com","ip":"1.2.3.4","port":443}\n'
            '{"host":"api.example.com","ip":"1.2.3.4","port":443}\n'
        )

        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "naabu_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, ports = run_naabu(["example.com", "api.example.com"], self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertEqual(ports, ["api.example.com:443"])

        meta_path = os.path.join(self.session_dir, "naabu_metadata.json")
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["raw_count"], 2)
        self.assertEqual(meta["valid_count"], 1)
        self.assertEqual(meta["duplicate_count"], 1)
        self.assertEqual(meta["invalid_count"], 0)
        self.assertEqual(meta["raw_count"], meta["valid_count"] + meta["invalid_count"] + meta["duplicate_count"])

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_05_invalid_port(self, mock_update, mock_docker):
        """
        Test 5: Invalid port
        Example: port = 70000 or negative port
        Expected: invalid_count += 1, does not enter ports.txt
        """
        raw_jsonl = (
            '{"host":"api.example.com","port":70000}\n'
            '{"host":"valid.example.com","port":8080}\n'
        )

        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "naabu_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, ports = run_naabu(["example.com"], self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertEqual(ports, ["valid.example.com:8080"])

        meta_path = os.path.join(self.session_dir, "naabu_metadata.json")
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["raw_count"], 2)
        self.assertEqual(meta["valid_count"], 1)
        self.assertEqual(meta["invalid_count"], 1)
        self.assertEqual(meta["duplicate_count"], 0)

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_06_malformed_json(self, mock_update, mock_docker):
        """
        Test 6: Malformed JSON
        Expected: invalid_count += 1, parser does not crash.
        """
        raw_jsonl = (
            'NOT_A_VALID_JSON\n'
            '{"host":"good.example.com","port":8443}\n'
            '{"broken_json: true\n'
        )

        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "naabu_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, ports = run_naabu(["example.com"], self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertEqual(ports, ["good.example.com:8443"])

        meta_path = os.path.join(self.session_dir, "naabu_metadata.json")
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["raw_count"], 3)
        self.assertEqual(meta["valid_count"], 1)
        self.assertEqual(meta["invalid_count"], 2)

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_07_no_forced_80_443(self, mock_update, mock_docker):
        """
        Test 7: No forced 80/443
        If Naabu returns only api.example.com:8080, do NOT inject :80 or :443.
        """
        raw_jsonl = '{"host":"api.example.com","port":8080}\n'

        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "naabu_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, ports = run_naabu(["example.com"], self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertEqual(ports, ["api.example.com:8080"])
        self.assertNotIn("api.example.com:80", ports)
        self.assertNotIn("api.example.com:443", ports)
        self.assertNotIn("example.com:80", ports)
        self.assertNotIn("example.com:443", ports)

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_08_shared_ip_attribution(self, mock_update, mock_docker):
        """
        Test 8: Shared IP attribution
        If a.example.com and b.example.com share the same IP 1.2.3.4,
        Naabu results must retain their distinct hostnames without arbitrary dictionary overwriting.
        """
        raw_jsonl = (
            '{"host":"a.example.com","ip":"1.2.3.4","port":443}\n'
            '{"host":"b.example.com","ip":"1.2.3.4","port":443}\n'
            '{"host":"1.2.3.4","ip":"1.2.3.4","port":80}\n'
        )

        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "naabu_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, ports = run_naabu(["example.com"], self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertIn("a.example.com:443", ports)
        self.assertIn("b.example.com:443", ports)
        self.assertIn("1.2.3.4:80", ports)
        self.assertEqual(len(ports), 3)

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_09_file_isolation(self, mock_update, mock_docker):
        """
        Test 9: File isolation
        Before and after Naabu: subdomains.txt must remain strictly unmodified.
        """
        mock_docker.return_value = (True, '{"host":"api.example.com","port":443}\n')

        ok, ports = run_naabu(["example.com", "api.example.com"], self.session_dir, self.scan_id)

        # subdomains.txt must have identical content
        with open(self.subdomains_file, "r", encoding="utf-8") as f:
            current_subdomains = f.read()
        self.assertEqual(current_subdomains, self.initial_subdomains)

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_10_counts_and_invariants(self, mock_update, mock_docker):
        """
        Test 10: Counts
        Verifies:
        - valid_count == number of lines in ports.txt
        - raw_count == valid_count + invalid_count + duplicate_count
        - open_endpoint_count == valid_count
        - unique_port_count is accurately computed (e.g. 443 on 2 hosts = 1 unique port)
        """
        raw_jsonl = (
            '{"host":"a.example.com","port":443}\n'
            '{"host":"b.example.com","port":443}\n'
            '{"host":"c.example.com","port":80}\n'
            '{"host":"a.example.com","port":443}\n'   # Duplicate
            '{"host":"bad.example.com","port":99999}\n' # Invalid
        )

        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "naabu_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, ports = run_naabu(["example.com"], self.session_dir, self.scan_id)

        self.assertTrue(ok)
        ports_path = os.path.join(self.session_dir, "ports.txt")
        with open(ports_path, "r", encoding="utf-8") as f:
            file_lines = [l.strip() for l in f if l.strip()]

        meta_path = os.path.join(self.session_dir, "naabu_metadata.json")
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        self.assertEqual(meta["raw_count"], 5)
        self.assertEqual(meta["valid_count"], 3)
        self.assertEqual(meta["duplicate_count"], 1)
        self.assertEqual(meta["invalid_count"], 1)
        self.assertEqual(meta["open_endpoint_count"], 3)
        self.assertEqual(meta["unique_port_count"], 2)  # 443 and 80
        self.assertEqual(meta["valid_count"], len(file_lines))
        self.assertEqual(
            meta["raw_count"],
            meta["valid_count"] + meta["invalid_count"] + meta["duplicate_count"]
        )

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_11_clean_slate(self, mock_update, mock_docker):
        """
        Pre-existing naabu_raw.jsonl and ports.txt must be cleared before a new execution.
        """
        raw_file = os.path.join(self.session_dir, "naabu_raw.jsonl")
        ports_file = os.path.join(self.session_dir, "ports.txt")
        with open(raw_file, "w", encoding="utf-8") as f:
            f.write("old raw data\n")
        with open(ports_file, "w", encoding="utf-8") as f:
            f.write("old:80\n")

        mock_docker.return_value = (False, "Command failure")

        ok, ports = run_naabu(["example.com"], self.session_dir, self.scan_id)

        self.assertFalse(ok)
        # Old ports.txt must not survive
        self.assertFalse(os.path.exists(ports_file))

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_12_naabu_command_and_configuration(self, mock_update, mock_docker):
        """
        Verifies:
        - Docker image tag is projectdiscovery/naabu:v2.6.1.
        - Timeout is >= 240 seconds.
        - Flags: -list, -p, -s c, -duc, -timeout 1s, -retries 1, -rate 300, -verify, -json, -o.
        - -Pn is NOT used.
        """
        mock_docker.return_value = (True, "")

        targets = ["example.com", "sub1.example.com", "sub2.example.com"]
        run_naabu(targets, self.session_dir, self.scan_id)

        self.assertTrue(mock_docker.called)
        call_kwargs = mock_docker.call_args[1] if mock_docker.call_args[1] else {}
        call_args_list = mock_docker.call_args[0] if mock_docker.call_args[0] else []

        image = call_kwargs.get("image") or (call_args_list[0] if len(call_args_list) > 0 else "")
        args = call_kwargs.get("args") or (call_args_list[1] if len(call_args_list) > 1 else [])
        timeout = call_kwargs.get("timeout") or (call_args_list[3] if len(call_args_list) > 3 else 0)

        self.assertEqual(image, "projectdiscovery/naabu:v2.6.1")
        self.assertGreaterEqual(timeout, 240)

        # Flag assertions
        self.assertIn("-list", args)
        self.assertIn("/data/naabu_targets.txt", args)
        self.assertIn("-p", args)
        self.assertIn(NAABU_PORTS, args)
        self.assertIn("-s", args)
        self.assertIn("c", args)
        self.assertIn("-duc", args)
        self.assertIn("-iv", args)
        self.assertEqual(args[args.index("-iv") + 1], "4")
        self.assertIn("-timeout", args)
        self.assertEqual(args[args.index("-timeout") + 1], "1s")
        self.assertIn("-retries", args)
        self.assertEqual(args[args.index("-retries") + 1], "1")
        self.assertIn("-rate", args)
        self.assertEqual(args[args.index("-rate") + 1], "300")
        self.assertIn("-verify", args)
        self.assertIn("-json", args)
        self.assertIn("-o", args)
        self.assertIn("/data/naabu_raw.jsonl", args)

        # Deprecated flag must NOT be present
        self.assertNotIn("-Pn", args)

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_13_stale_naabu_targets_not_reused(self, mock_update, mock_docker):
        """
        Requirement 1: Stale naabu_targets.txt must never be reused when current input is empty.
        If subdomains = [], Naabu must not run and must return completed with 0 ports.
        """
        naabu_targets_path = os.path.join(self.session_dir, "naabu_targets.txt")
        with open(naabu_targets_path, "w", encoding="utf-8") as f:
            f.write("stale.example.com\nstale2.example.com\n")

        ok, ports = run_naabu([], self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertEqual(ports, [])
        self.assertFalse(mock_docker.called, "run_docker_tool should NOT be called when input is empty!")

        # Check metadata
        meta_path = os.path.join(self.session_dir, "naabu_metadata.json")
        self.assertTrue(os.path.exists(meta_path))
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["status"], "completed")
        self.assertEqual(meta["input_count"], 0)
        self.assertEqual(meta["open_endpoint_count"], 0)

        # Check ports.txt
        ports_path = os.path.join(self.session_dir, "ports.txt")
        self.assertTrue(os.path.exists(ports_path))
        with open(ports_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read().strip(), "")

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_14_target_normalization_and_deduplication(self, mock_update, mock_docker):
        """
        Requirement 2: Targets must be normalized (lowercase, trailing-dot removed)
        and deduplicated while preserving order of first appearance.
        Input: ["API.Example.COM.", "api.example.com", "WWW.EXAMPLE.COM."]
        Output in naabu_targets.txt: api.example.com, www.example.com
        """
        mock_docker.return_value = (True, "")

        input_targets = ["API.Example.COM.", "api.example.com", "WWW.EXAMPLE.COM."]
        ok, ports = run_naabu(input_targets, self.session_dir, self.scan_id)

        self.assertTrue(ok)
        naabu_targets_path = os.path.join(self.session_dir, "naabu_targets.txt")
        self.assertTrue(os.path.exists(naabu_targets_path))
        with open(naabu_targets_path, "r", encoding="utf-8") as f:
            written_targets = [l.strip() for l in f if l.strip()]

        self.assertEqual(written_targets, ["api.example.com", "www.example.com"])

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_15_ip_only_and_host_preferred_json_parsing(self, mock_update, mock_docker):
        """
        Requirement 4:
        1. JSONL with IP only: {"ip":"1.2.3.4","port":443} -> 1.2.3.4:443
        2. JSONL with host and IP: {"host":"api.example.com","ip":"1.2.3.4","port":443}
           -> prefers host api.example.com:443 without inventing mapping.
        """
        raw_jsonl = (
            '{"ip":"1.2.3.4","port":443}\n'
            '{"host":"api.example.com","ip":"1.2.3.4","port":443}\n'
            '{"host":"dev.example.com","port":8080}\n'
        )

        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "naabu_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker

        ok, ports = run_naabu(["example.com"], self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertIn("1.2.3.4:443", ports)
        self.assertIn("api.example.com:443", ports)
        self.assertIn("dev.example.com:8080", ports)
        self.assertEqual(len(ports), 3)

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_16_status_updates_open_ports_count_all_paths(self, mock_update, mock_docker):
        """
        Requirement 5:
        Verify stats_update={"open_ports_count": ...} is called correctly in:
        1. Success path -> open_ports_count = valid_count
        2. Zero results -> open_ports_count = 0
        3. Failure path -> open_ports_count = 0
        """
        # 1. Success path
        raw_jsonl = '{"host":"api.example.com","port":443}\n{"host":"api.example.com","port":80}\n'
        def fake_docker_success(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "naabu_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_jsonl)
            return True, raw_jsonl

        mock_docker.side_effect = fake_docker_success
        ok, ports = run_naabu(["example.com"], self.session_dir, self.scan_id)
        self.assertTrue(ok)
        # Check last call to update_status
        last_call_kwargs = mock_update.call_args[1]
        self.assertEqual(last_call_kwargs.get("stats_update"), {"open_ports_count": 2})

        mock_update.reset_mock()

        # 2. Zero results path
        def fake_docker_empty(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "naabu_raw.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write("")
            return True, ""

        mock_docker.side_effect = fake_docker_empty
        ok, ports = run_naabu(["example.com"], self.session_dir, self.scan_id)
        self.assertTrue(ok)
        last_call_kwargs = mock_update.call_args[1]
        self.assertEqual(last_call_kwargs.get("stats_update"), {"open_ports_count": 0})

        mock_update.reset_mock()

        # 3. Failure path
        mock_docker.side_effect = None
        mock_docker.return_value = (False, "Naabu crashed")
        ok, ports = run_naabu(["example.com"], self.session_dir, self.scan_id)
        self.assertFalse(ok)
        last_call_kwargs = mock_update.call_args[1]
        self.assertEqual(last_call_kwargs.get("stats_update"), {"open_ports_count": 0})
        self.assertEqual(last_call_kwargs.get("tool_status"), {"naabu": "failed"})


if __name__ == "__main__":
    unittest.main()
