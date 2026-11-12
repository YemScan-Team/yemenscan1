"""
Unit and integration tests for the Subfinder stage in YemenScan.

Covers all acceptance criteria:
1. Only real Subfinder output is considered (no common subdomains, no DNS guessing).
2. Root domain is never classified as a subdomain (subdomains.txt and subdomains_count).
3. Raw output is preserved in subfinder_raw.txt as evidence.
4. Normalization, validation, and deduplication of subdomains.txt:
   - Trim whitespace, lowercase, remove trailing dot.
   - Deduplication.
   - Rejection of wildcards (*.example.com).
   - Rejection of IP addresses.
   - Rejection of URLs (https://api.example.com).
   - Acceptance of RFC hostnames only.
   - Strict root domain scope matching (host.endswith("." + root_domain) and host != root_domain).
5. Proper error handling when Subfinder fails:
   - success = False, subdomains = [], subdomains_count = 0.
   - No fallback or fake results generated.
6. Stale files from prior runs are cleaned before execution.
7. Downstream Naabu stage does not overwrite subdomains.txt (uses naabu_targets.txt).
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

from core.stage1_discovery import (
    normalize_and_validate_subdomain,
    run_subfinder,
    run_naabu,
    is_ip_address
)
from core.target_prioritizer import prioritize_hosts
from core.session import create_scan_session, get_status, update_status
from core.pipeline import run_full_pipeline


class TestSubfinderNormalizationAndValidation(unittest.TestCase):
    """Tests for individual normalization and validation rules."""

    def test_01_standard_subdomains(self):
        """
        Test 1:
        Input:
            www.example.com
            api.example.com
        Expected:
            www.example.com
            api.example.com
        """
        self.assertEqual(normalize_and_validate_subdomain("www.example.com", "example.com"), "www.example.com")
        self.assertEqual(normalize_and_validate_subdomain("api.example.com", "example.com"), "api.example.com")

    def test_02_normalization_and_deduplication(self):
        """
        Test 2:
        Input:
            API.Example.COM.
            api.example.com
        Expected:
            api.example.com (normalized to lowercase, trailing dot removed, duplicates merged)
        """
        norm1 = normalize_and_validate_subdomain("API.Example.COM.", "example.com")
        norm2 = normalize_and_validate_subdomain("api.example.com", "example.com")
        self.assertEqual(norm1, "api.example.com")
        self.assertEqual(norm2, "api.example.com")
        # In a list, deduplication yields exactly one
        deduped = list(dict.fromkeys([norm1, norm2]))
        self.assertEqual(deduped, ["api.example.com"])

    def test_03_root_domain_rejection(self):
        """
        Test 3:
        Input:
            example.com
            www.example.com
        Expected:
            www.example.com (example.com rejected)
        """
        self.assertIsNone(normalize_and_validate_subdomain("example.com", "example.com"))
        self.assertIsNone(normalize_and_validate_subdomain("example.com.", "example.com"))
        self.assertIsNone(normalize_and_validate_subdomain("EXAMPLE.COM", "example.com"))
        self.assertEqual(normalize_and_validate_subdomain("www.example.com", "example.com"), "www.example.com")

    def test_04_invalid_and_out_of_scope_rejection(self):
        """
        Test 4:
        Input:
            *.example.com
            outside.com
            evil-example.com
            example.com.evil.com
        Expected:
            [] (all rejected)
        """
        inputs = [
            "*.example.com",
            "outside.com",
            "evil-example.com",
            "example.com.evil.com"
        ]
        results = [normalize_and_validate_subdomain(i, "example.com") for i in inputs]
        valid = [r for r in results if r is not None]
        self.assertEqual(valid, [], f"Expected all invalid inputs to be rejected, got: {valid}")

    def test_05_reject_ips_urls_and_ports(self):
        """Rejects IP addresses, URLs with schemes, paths, and port numbers."""
        self.assertIsNone(normalize_and_validate_subdomain("192.168.1.1", "example.com"))
        self.assertIsNone(normalize_and_validate_subdomain("10.0.0.5", "example.com"))
        self.assertIsNone(normalize_and_validate_subdomain("https://api.example.com", "example.com"))
        self.assertIsNone(normalize_and_validate_subdomain("http://api.example.com/", "example.com"))
        self.assertIsNone(normalize_and_validate_subdomain("api.example.com/admin", "example.com"))
        self.assertIsNone(normalize_and_validate_subdomain("api.example.com:8080", "example.com"))

    def test_06_nested_subdomains_valid(self):
        """Accepts multi-level subdomains within scope."""
        self.assertEqual(
            normalize_and_validate_subdomain("dev.api.example.com", "example.com"),
            "dev.api.example.com"
        )
        self.assertEqual(
            normalize_and_validate_subdomain("stage.auth.services.example.com", "example.com"),
            "stage.auth.services.example.com"
        )


class TestSubfinderExecutionLifecycle(unittest.TestCase):
    """Tests for run_subfinder lifecycle, file preservation, and metadata."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ys_subfinder_test_")
        self.scan_id = "test_subfinder_session_001"
        self.session_dir = os.path.join(self.test_dir, self.scan_id)
        os.makedirs(self.session_dir, exist_ok=True)

        status_path = os.path.join(self.session_dir, "status.json")
        with open(status_path, "w", encoding="utf-8") as f:
            json.dump({
                "scan_id": self.scan_id,
                "target_domain": "example.com",
                "current_stage": "queued",
                "progress_percentage": 0,
                "logs": [],
                "is_completed": False,
                "has_error": False,
                "error_message": None,
                "stats": {"subdomains_count": 0}
            }, f)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_07_subfinder_success_pipeline_output(self, mock_update, mock_docker):
        """
        Verifies that subfinder_raw.txt holds the raw tool output,
        subdomains.txt holds the cleaned output,
        and subfinder_metadata.json captures accurate stats.
        """
        raw_output = "www.example.com\nAPI.Example.COM.\napi.example.com\nexample.com\n*.example.com\nevil-example.com\n"
        
        def fake_docker(*args, **kwargs):
            # Simulate subfinder writing to /data/subfinder_raw.txt
            raw_path = os.path.join(self.session_dir, "subfinder_raw.txt")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_output)
            return True, raw_output

        mock_docker.side_effect = fake_docker

        ok, subdomains = run_subfinder("example.com", self.session_dir, self.scan_id)

        self.assertTrue(ok)
        # Expected cleaned subdomains: www.example.com, api.example.com (example.com, wildcard, evil rejected; duplicate merged)
        self.assertEqual(sorted(subdomains), ["api.example.com", "www.example.com"])
        self.assertNotIn("example.com", subdomains)

        # 1. Verify subfinder_raw.txt exists and matches raw output
        raw_file = os.path.join(self.session_dir, "subfinder_raw.txt")
        self.assertTrue(os.path.exists(raw_file))
        with open(raw_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertEqual(content, raw_output)

        # 2. Verify subdomains.txt contains exactly the validated list
        clean_file = os.path.join(self.session_dir, "subdomains.txt")
        self.assertTrue(os.path.exists(clean_file))
        with open(clean_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertEqual(sorted(lines), ["api.example.com", "www.example.com"])

        # 3. Verify metadata
        meta_file = os.path.join(self.session_dir, "subfinder_metadata.json")
        self.assertTrue(os.path.exists(meta_file))
        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["tool"], "subfinder")
        self.assertEqual(meta["status"], "completed")
        self.assertEqual(meta["raw_count"], 6)
        self.assertEqual(meta["valid_count"], 2)
        self.assertEqual(meta["invalid_count"], 3)
        self.assertEqual(meta["duplicate_count"], 1)
        self.assertEqual(meta["raw_count"], meta["valid_count"] + meta["invalid_count"] + meta["duplicate_count"])
        self.assertEqual(meta["valid_count"], len(lines))

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_08_subfinder_zero_subdomains_found(self, mock_update, mock_docker):
        """
        When Subfinder discovers 0 subdomains, it must report 0 subdomains
        and NOT fabricate fallback subdomains or include root domain.
        """
        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "subfinder_raw.txt")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write("")
            return True, ""

        mock_docker.side_effect = fake_docker

        ok, subdomains = run_subfinder("example.com", self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertEqual(subdomains, [])
        self.assertEqual(len(subdomains), 0)

        # subdomains.txt must be empty
        clean_file = os.path.join(self.session_dir, "subdomains.txt")
        self.assertTrue(os.path.exists(clean_file))
        with open(clean_file, "r", encoding="utf-8") as f:
            self.assertEqual(f.read().strip(), "")

        # Metadata records 0 valid
        meta_file = os.path.join(self.session_dir, "subfinder_metadata.json")
        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["valid_count"], 0)
        self.assertEqual(meta["raw_count"], 0)

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_09_subfinder_failure_handling(self, mock_update, mock_docker):
        """
        Test 5:
        When Subfinder fails (non-zero exit code, timeout, container unavailable):
        Expected:
            success = False
            subdomains = []
            no fallback results created.
        """
        mock_docker.return_value = (False, "Process returned code 1: Subfinder binary failed")

        ok, subdomains = run_subfinder("example.com", self.session_dir, self.scan_id)

        self.assertFalse(ok)
        self.assertEqual(subdomains, [])

        # subdomains.txt must not contain fake data
        clean_file = os.path.join(self.session_dir, "subdomains.txt")
        self.assertFalse(os.path.exists(clean_file), "subdomains.txt should not exist on failure!")

        # Metadata must show failure
        meta_file = os.path.join(self.session_dir, "subfinder_metadata.json")
        self.assertTrue(os.path.exists(meta_file))
        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["tool"], "subfinder")
        self.assertEqual(meta["status"], "failed")
        self.assertEqual(meta["valid_count"], 0)
        self.assertIn("Subfinder binary failed", meta["error"])

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_10_clean_slate_no_stale_files(self, mock_update, mock_docker):
        """
        Requirement 6: Pre-existing subfinder_raw.txt and subdomains.txt
        must be wiped before Subfinder runs.
        """
        raw_file = os.path.join(self.session_dir, "subfinder_raw.txt")
        clean_file = os.path.join(self.session_dir, "subdomains.txt")
        
        # Pre-seed stale files
        with open(raw_file, "w", encoding="utf-8") as f:
            f.write("old.stale.example.com\n")
        with open(clean_file, "w", encoding="utf-8") as f:
            f.write("old.stale.example.com\n")

        # Simulate subfinder failing
        mock_docker.return_value = (False, "Command timed out")

        ok, subdomains = run_subfinder("example.com", self.session_dir, self.scan_id)

        self.assertFalse(ok)
        self.assertEqual(subdomains, [])
        # The stale subdomains.txt must have been removed, not reused
        self.assertFalse(os.path.exists(clean_file))


class TestNaabuIsolation(unittest.TestCase):
    """Tests ensuring Naabu does not overwrite subdomains.txt and uses naabu_targets.txt."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ys_naabu_iso_")
        self.scan_id = "test_naabu_iso_001"
        self.session_dir = os.path.join(self.test_dir, self.scan_id)
        os.makedirs(self.session_dir, exist_ok=True)

        # Write genuine subdomains.txt from Subfinder
        self.subdomains_file = os.path.join(self.session_dir, "subdomains.txt")
        with open(self.subdomains_file, "w", encoding="utf-8") as f:
            f.write("api.example.com\nwww.example.com\n")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    @patch("core.stage1_discovery._test_tcp_port")
    @patch("socket.gethostbyname")
    def test_11_naabu_does_not_overwrite_subdomains_file(self, mock_dns, mock_tcp, mock_update, mock_docker):
        """
        Requirement 7: Naabu must write to naabu_targets.txt,
        leaving subdomains.txt completely unchanged.
        """
        mock_dns.return_value = "192.0.2.1"
        mock_tcp.return_value = False
        mock_docker.return_value = (True, "")

        naabu_targets = ["example.com", "api.example.com", "www.example.com"]
        ok, ports = run_naabu(naabu_targets, self.session_dir, self.scan_id)

        # Verify subdomains.txt content was NOT overwritten
        with open(self.subdomains_file, "r", encoding="utf-8") as f:
            subdomains_content = f.read()
        self.assertEqual(subdomains_content, "api.example.com\nwww.example.com\n")

        # Verify naabu_targets.txt was created and used
        naabu_targets_file = os.path.join(self.session_dir, "naabu_targets.txt")
        self.assertTrue(os.path.exists(naabu_targets_file))
        with open(naabu_targets_file, "r", encoding="utf-8") as f:
            targets_content = f.read()
        self.assertIn("example.com", targets_content)
        self.assertIn("api.example.com", targets_content)
        self.assertIn("www.example.com", targets_content)


class TestTargetPrioritizer(unittest.TestCase):
    """Tests for prioritize_hosts include_root behavior and backward compatibility."""

    def test_12_prioritize_hosts_excludes_root_when_false(self):
        """When include_root is explicitly False, root domain is excluded from subdomains."""
        hosts = ["api.example.com", "example.com", "www.example.com"]
        result = prioritize_hosts(hosts, "example.com", include_root=False)
        self.assertEqual(result, ["www.example.com", "api.example.com"])
        self.assertNotIn("example.com", result)

    def test_13_prioritize_hosts_empty_returns_empty_when_false(self):
        """When hosts is empty and include_root is False, returns empty list (0 subdomains)."""
        result = prioritize_hosts([], "example.com", include_root=False)
        self.assertEqual(result, [])

    def test_14_prioritize_hosts_includes_root_when_requested(self):
        """When include_root is True, root domain is at index 0."""
        hosts = ["api.example.com", "www.example.com"]
        result = prioritize_hosts(hosts, "example.com", include_root=True)
        self.assertEqual(result[0], "example.com")
        self.assertIn("www.example.com", result)
        self.assertIn("api.example.com", result)

    def test_15_prioritize_hosts_default_preserves_legacy_compatibility(self):
        """
        Regression test: default call prioritize_hosts(hosts, domain) must preserve legacy
        behavior (include_root=True) so other stages and callers that rely on root domain
        at index 0 are NOT broken.
        """
        hosts = ["api.example.com", "www.example.com"]
        # Call with default arguments (no include_root specified)
        result = prioritize_hosts(hosts, "example.com")
        self.assertEqual(result[0], "example.com", "Default prioritize_hosts must include root domain at index 0 for backward compatibility!")
        self.assertIn("www.example.com", result)
        self.assertIn("api.example.com", result)

        # Default on empty list returns root domain
        empty_res = prioritize_hosts([], "example.com")
        self.assertEqual(empty_res, ["example.com"])


class TestSubfinderInvariantsAndConfiguration(unittest.TestCase):
    """Tests for exact duplicate separation, timeout configuration, and fixed docker tag."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ys_subfinder_inv_")
        self.scan_id = "test_subfinder_inv_001"
        self.session_dir = os.path.join(self.test_dir, self.scan_id)
        os.makedirs(self.session_dir, exist_ok=True)

        status_path = os.path.join(self.session_dir, "status.json")
        with open(status_path, "w", encoding="utf-8") as f:
            json.dump({
                "scan_id": self.scan_id,
                "target_domain": "example.com",
                "stats": {"subdomains_count": 0}
            }, f)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_16_duplicate_does_not_increase_invalid_count(self, mock_update, mock_docker):
        """
        Verifies:
        - Duplicate does NOT increment invalid_count.
        - duplicate_count is accurate.
        - Invariant: raw_count == valid_count + invalid_count + duplicate_count.
        - Invariant: valid_count == number of lines in subdomains.txt.
        """
        # 8 raw lines:
        # - 1 valid unique: api.example.com
        # - 3 duplicates: API.example.com, api.example.com., aPi.example.com
        # - 4 invalid: *.example.com (wildcard), https://test.com (url), 10.0.0.1 (ip), example.com (root)
        raw_lines = [
            "api.example.com",
            "API.example.com",
            "api.example.com.",
            "aPi.example.com",
            "*.example.com",
            "https://test.com",
            "10.0.0.1",
            "example.com"
        ]
        raw_text = "\n".join(raw_lines) + "\n"

        def fake_docker(*args, **kwargs):
            raw_path = os.path.join(self.session_dir, "subfinder_raw.txt")
            with open(raw_path, "w", encoding="utf-8") as rf:
                rf.write(raw_text)
            return True, raw_text

        mock_docker.side_effect = fake_docker

        ok, subdomains = run_subfinder("example.com", self.session_dir, self.scan_id)

        self.assertTrue(ok)
        self.assertEqual(subdomains, ["api.example.com"])

        # Check subdomains.txt lines
        sub_file = os.path.join(self.session_dir, "subdomains.txt")
        with open(sub_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        # Check metadata file
        meta_file = os.path.join(self.session_dir, "subfinder_metadata.json")
        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)

        self.assertEqual(meta["raw_count"], 8)
        self.assertEqual(meta["valid_count"], 1)
        self.assertEqual(meta["invalid_count"], 4, "Invalid count should only include invalid items, not duplicates!")
        self.assertEqual(meta["duplicate_count"], 3, "Duplicate count must match the 3 duplicate variants!")
        
        # Invariants:
        self.assertEqual(
            meta["raw_count"],
            meta["valid_count"] + meta["invalid_count"] + meta["duplicate_count"],
            "raw_count must strictly equal valid_count + invalid_count + duplicate_count!"
        )
        self.assertEqual(
            meta["valid_count"],
            len(lines),
            "valid_count must strictly match number of lines in subdomains.txt!"
        )

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_17_timeout_and_fixed_docker_tag(self, mock_update, mock_docker):
        """
        Verifies:
        - run_docker_tool timeout is greater than the total max time allowed for Subfinder (-max-time 3 = 180s).
        - Fixed Docker image tag is used instead of :latest.
        - -timeout and -max-time flags are passed correctly.
        """
        mock_docker.return_value = (True, "")

        run_subfinder("example.com", self.session_dir, self.scan_id)

        self.assertTrue(mock_docker.called)
        call_kwargs = mock_docker.call_args[1] if mock_docker.call_args[1] else {}
        call_args_list = mock_docker.call_args[0] if mock_docker.call_args[0] else []

        # Find image, args, timeout
        image = call_kwargs.get("image") or (call_args_list[0] if len(call_args_list) > 0 else "")
        args = call_kwargs.get("args") or (call_args_list[1] if len(call_args_list) > 1 else [])
        timeout = call_kwargs.get("timeout") or (call_args_list[3] if len(call_args_list) > 3 else 0)

        # 1. Image must use fixed tag, not :latest
        self.assertNotEqual(image, "projectdiscovery/subfinder:latest", "Must use a pinned release tag instead of :latest!")
        self.assertEqual(image, "projectdiscovery/subfinder:v2.17.0")

        # 2. Timeout must exceed 180s (-max-time 3)
        self.assertGreaterEqual(timeout, 210, "Docker timeout must be at least 210s to allow 3-minute max-time + buffer!")

        # 3. CLI arguments must retain -timeout 15 and -max-time 3
        self.assertIn("-timeout", args)
        idx_timeout = args.index("-timeout")
        self.assertEqual(args[idx_timeout + 1], "15")

        self.assertIn("-max-time", args)
        idx_maxtime = args.index("-max-time")
        self.assertEqual(args[idx_maxtime + 1], "3")


if __name__ == "__main__":
    unittest.main()
