import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
import json
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from core.stage3_vulnerabilities import (
    run_nuclei,
    run_optimized_nuclei,
    run_standalone_nuclei,
    prepare_nuclei_targets,
    parse_nuclei_json_output,
    normalize_target_origin,
    normalize_matched_url,
    write_nuclei_template_manifest,
    clean_nuclei_session_artifacts,
    NUCLEI_DOCKER_IMAGE,
    NUCLEI_ENGINE_VERSION,
    NUCLEI_ENGINE_DIGEST,
    NUCLEI_TEMPLATES_OFFICIAL_DIR,
    NUCLEI_TEMPLATES_VERSION,
    NUCLEI_TEMPLATES_COMMIT,
    NUCLEI_TEMPLATES_CHECKSUM,
    NUCLEI_SAFE_FLAGS,
)
from core.nuclei_template_selector import (
    generate_nuclei_scan_plan,
    SafeManifestManager,
    OriginCircuitBreaker,
    extract_origin_signals,
    AdaptiveTemplateSelector,
    classify_technology,
    classify_template_content,
    estimate_request_cost
)


class TestNucleiStage(unittest.TestCase):
    """
    Comprehensive test suite for the ProjectDiscovery Nuclei vulnerability scanning stage in YemenScan.
    Validates official Docker pinning, safe execution flags, strict provenance,
    classification truth, deduplication, metadata invariants, and zero native fallback.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_nuclei_")
        self.scan_id = "test_scan_nuclei_123"

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    # --------------------------------------------------------------------------
    # 1. Pinned Image, Version & Digest Verification
    # --------------------------------------------------------------------------
    def test_01_pinned_docker_image_and_digest(self):
        """1. Verify Docker image uses exact tag and sha256 digest with no latest tag."""
        expected_digest = "sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb"
        expected_image = f"projectdiscovery/nuclei:v3.11.1@{expected_digest}"
        self.assertEqual(NUCLEI_DOCKER_IMAGE, expected_image)
        self.assertEqual(NUCLEI_ENGINE_VERSION, "v3.11.1")
        self.assertEqual(NUCLEI_ENGINE_DIGEST, expected_digest)
        self.assertNotIn("latest", NUCLEI_DOCKER_IMAGE)

    def test_02_official_templates_pinning(self):
        """2. Verify official templates metadata constants and directory."""
        self.assertEqual(NUCLEI_TEMPLATES_VERSION, "v10.5.1")
        self.assertEqual(NUCLEI_TEMPLATES_COMMIT, "79fb682760ab3d5b0e22afbb44709353cbebf023")
        self.assertEqual(NUCLEI_TEMPLATES_CHECKSUM, "8a8a34ea672e2ee3674092112e5e6934309fc9aa")
        self.assertTrue(os.path.basename(NUCLEI_TEMPLATES_OFFICIAL_DIR) == "nuclei_templates_official")

    # --------------------------------------------------------------------------
    # 2. Safe Default Profile & Required Flags
    # --------------------------------------------------------------------------
    def test_03_safe_profile_flags_enforced(self):
        """3. Verify safe profile flags: -dut, -pt http, -severity, -etags, -ni, -lna, -iv 4, -duc."""
        self.assertIn("-dut", NUCLEI_SAFE_FLAGS)
        self.assertIn("-ni", NUCLEI_SAFE_FLAGS)
        self.assertIn("-lna", NUCLEI_SAFE_FLAGS)
        self.assertIn("-duc", NUCLEI_SAFE_FLAGS)
        self.assertIn("-pt", NUCLEI_SAFE_FLAGS)
        pt_idx = NUCLEI_SAFE_FLAGS.index("-pt")
        self.assertEqual(NUCLEI_SAFE_FLAGS[pt_idx + 1], "http")
        sev_idx = NUCLEI_SAFE_FLAGS.index("-severity")
        self.assertEqual(NUCLEI_SAFE_FLAGS[sev_idx + 1], "medium,high,critical")
        etags_idx = NUCLEI_SAFE_FLAGS.index("-etags")
        self.assertEqual(NUCLEI_SAFE_FLAGS[etags_idx + 1], "dos,fuzz,bruteforce,intrusive,local")

    def test_04_intrusive_and_exploit_flags_disallowed(self):
        """4. Verify dangerous flags (-code, -file, -esc, -egm, -itags, -dast, -fuzz) are not in safe flags."""
        forbidden_flags = ["-code", "-file", "-esc", "-egm", "-itags", "-dast", "-fuzz"]
        for f in forbidden_flags:
            self.assertNotIn(f, NUCLEI_SAFE_FLAGS)

    # --------------------------------------------------------------------------
    # 3. Target Extraction, Normalization & Provenance
    # --------------------------------------------------------------------------
    def test_05_target_origin_normalization(self):
        """5. Verify normalize_target_origin normalizes scheme, host, and port."""
        self.assertEqual(normalize_target_origin("https://api.example.com:443/v1/users"), "https://api.example.com")
        self.assertEqual(normalize_target_origin("http://portal.example.com:80/"), "http://portal.example.com")
        self.assertEqual(normalize_target_origin("https://portal.example.com:8443/api"), "https://portal.example.com:8443")
        self.assertEqual(normalize_target_origin("HTTP://SUB.EXAMPLE.COM."), "http://sub.example.com")
        self.assertIsNone(normalize_target_origin("ftp://invalid.com"))
        self.assertIsNone(normalize_target_origin(""))

    def test_06_prepare_targets_from_active_urls(self):
        """6. Verify prepare_nuclei_targets extracts canonical origins and deduplicates."""
        active_urls = [
            "https://api.example.com/v1/users",
            "https://api.example.com/v1/products",
            "http://portal.example.com:8080/dashboard",
            "https://api.example.com:443/"
        ]
        active_file = os.path.join(self.test_dir, "active_urls.txt")
        with open(active_file, "w", encoding="utf-8") as f:
            for u in active_urls:
                f.write(f"{u}\n")

        targets = prepare_nuclei_targets(self.test_dir)
        expected = ["http://portal.example.com:8080", "https://api.example.com"]
        self.assertEqual(targets, expected)

        # Check file on disk
        targets_file = os.path.join(self.test_dir, "nuclei_targets.txt")
        self.assertTrue(os.path.exists(targets_file))
        with open(targets_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertEqual(lines, expected)

    def test_07_prepare_targets_clean_slate(self):
        """7. Verify prepare_nuclei_targets deletes stale artifacts from prior runs."""
        stale_files = ["nuclei_raw.jsonl", "nuclei_findings.json", "nuclei_metadata.json", "nuclei_stderr.log"]
        for sf in stale_files:
            fp = os.path.join(self.test_dir, sf)
            with open(fp, "w", encoding="utf-8") as f:
                f.write("old data")

        active_file = os.path.join(self.test_dir, "active_urls.txt")
        with open(active_file, "w", encoding="utf-8") as f:
            f.write("https://api.example.com\n")

        prepare_nuclei_targets(self.test_dir)

        for sf in stale_files:
            fp = os.path.join(self.test_dir, sf)
            self.assertFalse(os.path.exists(fp), f"Stale file {sf} should have been deleted!")

    def test_08_empty_targets_handling(self):
        """8. Verify empty active_urls yields zero targets, metadata status completed, and no docker call."""
        with patch("core.stage3_vulnerabilities.run_docker_tool") as mock_dock:
            targets = prepare_nuclei_targets(self.test_dir)
            self.assertEqual(targets, [])
            mock_dock.assert_not_called()

            meta_file = os.path.join(self.test_dir, "nuclei_metadata.json")
            self.assertTrue(os.path.exists(meta_file))
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            self.assertEqual(meta["input_count"], 0)
            self.assertEqual(meta["raw_count"], 0)
            self.assertEqual(meta["valid_count"], 0)
            self.assertEqual(meta["status"], "completed")

            findings_file = os.path.join(self.test_dir, "nuclei_findings.json")
            self.assertTrue(os.path.exists(findings_file))
            with open(findings_file, "r", encoding="utf-8") as f:
                self.assertEqual(json.load(f), [])

            # Run nuclei with empty targets
            ok, findings = run_nuclei(self.test_dir, self.scan_id)
            self.assertTrue(ok)
            self.assertEqual(findings, [])
            mock_dock.assert_not_called()

    # --------------------------------------------------------------------------
    # 4. Docker Execution & Arguments
    # --------------------------------------------------------------------------
    def test_09_docker_execution_arguments_and_volumes(self):
        """9. Verify run_nuclei passes official image, volumes, and adaptive flags to run_docker_tool."""
        tf = os.path.join(self.test_dir, "nuclei_targets.txt")
        with open(tf, "w", encoding="utf-8") as f:
            f.write("https://academy.hackthebox.com\n")

        with patch("core.stage3_vulnerabilities.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, "")
            ok, findings = run_nuclei(self.test_dir, self.scan_id)

            self.assertTrue(ok)
            mock_dock.assert_called_once()
            call_kwargs = mock_dock.call_args[1]

            self.assertEqual(call_kwargs["image"], NUCLEI_DOCKER_IMAGE)
            self.assertEqual(call_kwargs["volume_dir"], self.test_dir)
            self.assertIn(os.path.basename(call_kwargs["extra_volumes"][0][0]), ("nuclei_runtime_templates", "nuclei_templates_official"))
            self.assertEqual(call_kwargs["extra_volumes"][0][1], "/opt/nuclei-templates")

            args = call_kwargs["args"]
            self.assertIn("-l", args)
            self.assertIn("/data/nuclei_targets_profile-001.txt", args)
            self.assertIn("-t", args)
            self.assertIn("/data/selected_templates_profile-001.txt", args)
            self.assertIn("-jsonl", args)
            self.assertIn("-o", args)
            self.assertIn("/data/nuclei_raw_profile-001.jsonl", args)
            self.assertIn("-dut", args)
            self.assertIn("-ni", args)
            self.assertIn("-lna", args)
            self.assertIn("-iv", args)
            self.assertIn("4", args)
            self.assertIn("-rl", args)
            self.assertIn("10", args)
            self.assertIn("-c", args)
            self.assertIn("5", args)
            self.assertIn("-bs", args)
            self.assertIn("5", args)
            self.assertIn("-timeout", args)
            self.assertIn("5", args)
            self.assertIn("-retries", args)
            self.assertIn("0", args)
            self.assertIn("-duc", args)
            self.assertIn("-nc", args)
            self.assertIn("-silent", args)

    def test_10_dynamic_timeout_calculation(self):
        """10. Verify dynamic execution timeout is scaled per profile based on template budget."""
        targets = [f"https://sub{i}.example.com" for i in range(25)]
        tf = os.path.join(self.test_dir, "nuclei_targets.txt")
        with open(tf, "w", encoding="utf-8") as f:
            for t in targets:
                f.write(f"{t}\n")

        with patch("core.stage3_vulnerabilities.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, "")
            run_nuclei(self.test_dir, self.scan_id)
            # Baseline 19 safe templates * 8s = 152 seconds, bounded by min 180s
            self.assertEqual(mock_dock.call_args[1]["timeout"], 180)

    # --------------------------------------------------------------------------
    # 5. Strict Zero Fallback on Failure
    # --------------------------------------------------------------------------
    def test_11_no_python_fallback_on_docker_failure(self):
        """11. Verify Docker failure returns False, [] and NEVER falls back to native requests."""
        tf = os.path.join(self.test_dir, "nuclei_targets.txt")
        with open(tf, "w", encoding="utf-8") as f:
            f.write("https://api.example.com\n")

        with patch("core.stage3_vulnerabilities.run_docker_tool") as mock_dock:
            with patch("core.stage3_vulnerabilities.run_native_nuclei_fallback") as mock_fb:
                mock_dock.return_value = (False, "Docker daemon connection error")

                ok, findings = run_nuclei(self.test_dir, self.scan_id)

                self.assertFalse(ok)
                self.assertEqual(findings, [])
                mock_fb.assert_not_called()

                meta_file = os.path.join(self.test_dir, "nuclei_metadata.json")
                self.assertTrue(os.path.exists(meta_file))
                with open(meta_file, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                self.assertEqual(meta["status"], "failed")
                self.assertEqual(meta["finding_count"], 0)
                self.assertIn("Docker daemon connection error", meta["error"])

                stderr_file = os.path.join(self.test_dir, "nuclei_stderr.log")
                self.assertTrue(os.path.exists(stderr_file))
                with open(stderr_file, "r", encoding="utf-8") as f:
                    self.assertIn("Docker daemon connection error", f.read())

    # --------------------------------------------------------------------------
    # 6. Classification Truth (No Hallucinations)
    # --------------------------------------------------------------------------
    def test_12_cve_extracted_strictly_from_classification(self):
        """12. CVE, CWE, CVSS score and vector extracted strictly from info.classification."""
        raw_record = {
            "template-id": "cve-2021-26084",
            "info": {
                "name": "Confluence OGNL Injection",
                "severity": "critical",
                "description": "Critical RCE flaw in Confluence.",
                "remediation": "Upgrade version.",
                "tags": ["cve", "rce"],
                "classification": {
                    "cve-id": ["CVE-2021-26084"],
                    "cwe-id": ["CWE-94"],
                    "cvss-score": 9.8,
                    "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            },
            "matcher-name": "body-check",
            "matched-at": "https://api.example.com/pages/createpage.action"
        }
        raw_file = os.path.join(self.test_dir, "nuclei_raw.jsonl")
        with open(raw_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(raw_record) + "\n")

        findings, counts = parse_nuclei_json_output(raw_file, valid_target_origins={"https://api.example.com"})
        self.assertEqual(len(findings), 1)
        f0 = findings[0]
        self.assertEqual(f0["cve_id"], "CVE-2021-26084")
        self.assertEqual(f0["cwe_id"], "CWE-94")
        self.assertEqual(f0["cvss_score"], 9.8)
        self.assertEqual(f0["cvss_vector"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(f0["finding_status"], "scanner_match")
        self.assertEqual(f0["source"], "nuclei")
        self.assertEqual(f0["template_source"], "official-nuclei-templates")
        self.assertEqual(f0["templates_version"], "v10.5.1")
        self.assertTrue(f0["template_signed"])

    def test_13_no_cve_hallucination_when_classification_missing(self):
        """13. When info.classification is missing or lacks cve-id, cve_id MUST be None, never guessed from template-id."""
        raw_record = {
            "template-id": "cve-2024-99999-fake-exploit",
            "info": {
                "name": "CVE-2024-99999 Title",
                "severity": "high",
                "description": "A flaw mentioning CVE-2024-99999 in description",
                "tags": ["cve", "cve2024"]
                # Notice: NO classification block!
            },
            "matcher-name": "status-check",
            "matched-at": "https://api.example.com/test"
        }
        raw_file = os.path.join(self.test_dir, "nuclei_raw.jsonl")
        with open(raw_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(raw_record) + "\n")

        findings, counts = parse_nuclei_json_output(raw_file, valid_target_origins={"https://api.example.com"})
        self.assertEqual(len(findings), 1)
        f0 = findings[0]
        self.assertIsNone(f0["cve_id"])
        self.assertIsNone(f0["cwe_id"])
        self.assertIsNone(f0["cvss_score"])
        self.assertIsNone(f0["cvss_vector"])

    # --------------------------------------------------------------------------
    # 7. Strict Provenance & Out-of-Scope Rejection
    # --------------------------------------------------------------------------
    def test_14_provenance_rejects_out_of_scope_findings(self):
        """14. Findings targeting origins not present in valid_target_origins are rejected as out_of_scope."""
        in_scope_record = {
            "template-id": "git-config",
            "info": {"name": "Git Config", "severity": "medium"},
            "matched-at": "https://api.example.com/.git/config"
        }
        out_of_scope_record = {
            "template-id": "git-config",
            "info": {"name": "Git Config", "severity": "medium"},
            "matched-at": "https://malicious-external.com/.git/config"
        }
        scheme_mismatch_record = {
            "template-id": "git-config",
            "info": {"name": "Git Config", "severity": "medium"},
            "matched-at": "http://api.example.com/.git/config"  # HTTP vs HTTPS
        }

        raw_file = os.path.join(self.test_dir, "nuclei_raw.jsonl")
        with open(raw_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(in_scope_record) + "\n")
            f.write(json.dumps(out_of_scope_record) + "\n")
            f.write(json.dumps(scheme_mismatch_record) + "\n")

        valid_origins = {"https://api.example.com"}
        findings, counts = parse_nuclei_json_output(raw_file, valid_target_origins=valid_origins)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["url"], "https://api.example.com/.git/config")
        self.assertEqual(counts["raw_count"], 3)
        self.assertEqual(counts["valid_count"], 1)
        self.assertEqual(counts["out_of_scope_count"], 2)

    # --------------------------------------------------------------------------
    # 8. Deduplication Logic
    # --------------------------------------------------------------------------
    def test_15_deduplication_on_template_url_matcher(self):
        """15. Findings with identical template_id, normalized_url, and matcher_name are deduplicated."""
        record1 = {
            "template-id": "swagger-api",
            "info": {"name": "Swagger UI", "severity": "low"},
            "matcher-name": "title-match",
            "matched-at": "https://api.example.com/swagger-ui.html"
        }
        record2 = {
            "template-id": "swagger-api",
            "info": {"name": "Swagger UI", "severity": "low"},
            "matcher-name": "title-match",
            "matched-at": "https://api.example.com:443/swagger-ui.html"  # Same URL after normalization
        }
        record3 = {
            "template-id": "swagger-api",
            "info": {"name": "Swagger UI", "severity": "low"},
            "matcher-name": "body-match",  # Different matcher
            "matched-at": "https://api.example.com/swagger-ui.html"
        }

        raw_file = os.path.join(self.test_dir, "nuclei_raw.jsonl")
        with open(raw_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(record1) + "\n")
            f.write(json.dumps(record2) + "\n")
            f.write(json.dumps(record3) + "\n")

        valid_origins = {"https://api.example.com"}
        findings, counts = parse_nuclei_json_output(raw_file, valid_target_origins=valid_origins)

        self.assertEqual(len(findings), 2)
        self.assertEqual(counts["raw_count"], 3)
        self.assertEqual(counts["valid_count"], 2)
        self.assertEqual(counts["duplicate_count"], 1)

    # --------------------------------------------------------------------------
    # 9. Invariants & Malformed Input
    # --------------------------------------------------------------------------
    def test_16_metadata_mathematical_invariants(self):
        """16. raw_count == valid_count + invalid_count + duplicate_count + out_of_scope_count."""
        lines = [
            json.dumps({"template-id": "t1", "info": {"name": "T1", "severity": "high"}, "matched-at": "https://api.example.com/p1"}),
            json.dumps({"template-id": "t2", "info": {"name": "T2", "severity": "medium"}, "matched-at": "https://api.example.com/p2"}),
            json.dumps({"template-id": "t1", "info": {"name": "T1", "severity": "high"}, "matched-at": "https://api.example.com/p1"}), # duplicate
            json.dumps({"template-id": "t3", "info": {"name": "T3", "severity": "low"}, "matched-at": "https://external.com/p3"}),      # out of scope
            "{ malformed json string ",                                                                                                    # invalid json
            json.dumps({"missing-template-id": True, "info": {}, "matched-at": "https://api.example.com"}),                                # invalid schema
            "   ",                                                                                                                         # whitespace line (skipped)
        ]
        raw_file = os.path.join(self.test_dir, "nuclei_raw.jsonl")
        with open(raw_file, "w", encoding="utf-8") as f:
            for l in lines:
                f.write(l + "\n")

        valid_origins = {"https://api.example.com"}
        findings, counts = parse_nuclei_json_output(raw_file, valid_target_origins=valid_origins)

        self.assertEqual(counts["raw_count"], 6)  # 6 non-empty lines
        self.assertEqual(counts["valid_count"], 2)
        self.assertEqual(counts["duplicate_count"], 1)
        self.assertEqual(counts["out_of_scope_count"], 1)
        self.assertEqual(counts["invalid_count"], 2)

        invariant_sum = (
            counts["valid_count"]
            + counts["invalid_count"]
            + counts["duplicate_count"]
            + counts["out_of_scope_count"]
        )
        self.assertEqual(counts["raw_count"], invariant_sum)
        self.assertEqual(len(findings), counts["valid_count"])

    # --------------------------------------------------------------------------
    # 10. Manifest File Structure
    # --------------------------------------------------------------------------
    def test_17_manifest_generation(self):
        """17. Verify nuclei_template_manifest.json contents and immutability."""
        manifest = write_nuclei_template_manifest(self.test_dir)
        manifest_path = os.path.join(self.test_dir, "nuclei_template_manifest.json")
        self.assertTrue(os.path.exists(manifest_path))

        with open(manifest_path, "r", encoding="utf-8") as f:
            disk_manifest = json.load(f)

        self.assertEqual(disk_manifest["templates_path"], "/opt/nuclei-templates")
        self.assertEqual(disk_manifest["templates_version"], "v10.5.1")
        self.assertEqual(disk_manifest["templates_commit"], "79fb682760ab3d5b0e22afbb44709353cbebf023")
        self.assertEqual(disk_manifest["templates_tree_checksum"], "8a8a34ea672e2ee3674092112e5e6934309fc9aa")
        self.assertEqual(disk_manifest["signature_verification"], "enforced_dut")
        self.assertEqual(disk_manifest["protocol_scope"], ["http"])
        self.assertEqual(disk_manifest["severities"], ["medium", "high", "critical"])
        self.assertEqual(disk_manifest["excluded_tags"], ["dos", "fuzz", "bruteforce", "intrusive", "local"])

    # --------------------------------------------------------------------------
    # 11. Standalone Nuclei Scanner
    # --------------------------------------------------------------------------
    def test_18_standalone_nuclei_no_fallback(self):
        """18. Verify run_standalone_nuclei uses Docker and returns empty list on failure without fallback."""
        with patch("core.stage3_vulnerabilities.run_docker_tool") as mock_dock:
            mock_dock.return_value = (False, "Docker failed")
            findings = run_standalone_nuclei("https://example.com")
            self.assertEqual(findings, [])
            mock_dock.assert_called_once()
            self.assertEqual(mock_dock.call_args[1]["image"], NUCLEI_DOCKER_IMAGE)

    # --------------------------------------------------------------------------
    # 12. Optimized Nuclei Backward Compatibility
    # --------------------------------------------------------------------------
    def test_19_optimized_nuclei_compatibility(self):
        """19. Verify run_optimized_nuclei forwards to run_nuclei seamlessly."""
        with patch("core.stage3_vulnerabilities.run_nuclei") as mock_run:
            mock_run.return_value = (True, [])
            ok, findings = run_optimized_nuclei(self.test_dir, tech_list=["nginx", "php"], scan_id=self.scan_id)
            self.assertTrue(ok)
            mock_run.assert_called_once_with(session_dir=self.test_dir, scan_id=self.scan_id)

            tech_file = os.path.join(self.test_dir, "tech_profile.json")
            self.assertTrue(os.path.exists(tech_file))

    # --------------------------------------------------------------------------
    # 13. Legacy Templates Isolation & Security
    # --------------------------------------------------------------------------
    def test_20_legacy_templates_never_mounted(self):
        """20. Ensure legacy custom templates directory (nuclei_templates) is never mounted into the container."""
        tf = os.path.join(self.test_dir, "nuclei_targets.txt")
        with open(tf, "w", encoding="utf-8") as f:
            f.write("https://api.example.com\n")

        with patch("core.stage3_vulnerabilities.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, "")
            run_nuclei(self.test_dir, self.scan_id)

            extra_vols = mock_dock.call_args[1]["extra_volumes"]
            for host_p, cont_p in extra_vols:
                self.assertNotEqual(os.path.basename(host_p), "nuclei_templates", "Legacy custom templates must never be mounted!")
                self.assertIn(os.path.basename(host_p), ("nuclei_runtime_templates", "nuclei_templates_official"))

    def test_21_zero_findings_success_status(self):
        """21. When Docker succeeds with 0 findings, metadata reports completed with 0 findings."""
        tf = os.path.join(self.test_dir, "nuclei_targets.txt")
        with open(tf, "w", encoding="utf-8") as f:
            f.write("https://api.example.com\n")

        with patch("core.stage3_vulnerabilities.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, "")
            # Empty raw file simulated
            raw_file = os.path.join(self.test_dir, "nuclei_raw.jsonl")
            with open(raw_file, "w", encoding="utf-8") as rf:
                pass

            ok, findings = run_nuclei(self.test_dir, self.scan_id)
            self.assertTrue(ok)
            self.assertEqual(findings, [])

            meta_file = os.path.join(self.test_dir, "nuclei_metadata.json")
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            self.assertEqual(meta["status"], "completed")
            self.assertEqual(meta["finding_count"], 0)
            self.assertEqual(meta["raw_count"], 0)

    def test_22_classification_string_or_list_variations(self):
        """22. Handles classification fields whether represented as string, list, or alternate metric keys."""
        record = {
            "template-id": "cve-test-var",
            "info": {
                "name": "Variation Test",
                "severity": "medium",
                "classification": {
                    "cve_id": "cve-2023-1111",
                    "cwe_id": "cwe-79",
                    "cvss_score": "6.1",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
                }
            },
            "matched-at": "https://api.example.com/search"
        }
        raw_file = os.path.join(self.test_dir, "nuclei_raw.jsonl")
        with open(raw_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        findings, counts = parse_nuclei_json_output(raw_file, valid_target_origins={"https://api.example.com"})
        self.assertEqual(len(findings), 1)
        f0 = findings[0]
        self.assertEqual(f0["cve_id"], "CVE-2023-1111")
        self.assertEqual(f0["cwe_id"], "CWE-79")
        self.assertEqual(f0["cvss_score"], 6.1)
        self.assertEqual(f0["cvss_vector"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")

    def test_23_no_native_fallback_on_exception(self):
        """23. If run_docker_tool raises an unexpected exception, error is caught and native fallback is never invoked."""
        tf = os.path.join(self.test_dir, "nuclei_targets.txt")
        with open(tf, "w", encoding="utf-8") as f:
            f.write("https://api.example.com\n")

        with patch("core.stage3_vulnerabilities.run_docker_tool") as mock_dock:
            with patch("core.stage3_vulnerabilities.run_native_nuclei_fallback") as mock_fb:
                mock_dock.side_effect = RuntimeError("Docker process killed")
                with self.assertRaises(RuntimeError):
                    run_nuclei(self.test_dir, self.scan_id)
                mock_fb.assert_not_called()

    # --------------------------------------------------------------------------
    # 14. Section 34 Adaptive & Safe Architecture Test Suite (Items 1 - 27)
    # --------------------------------------------------------------------------
    def test_24_httpx_technology_selects_related_templates(self):
        """1. httpx technology selects related templates (e.g. WordPress, PHP)."""
        active_json = os.path.join(self.test_dir, "active_urls.json")
        with open(active_json, "w", encoding="utf-8") as f:
            f.write(json.dumps({"url": "https://wp.example.com", "tech": ["WordPress", "PHP"]}) + "\n")

        plan = generate_nuclei_scan_plan(self.test_dir, origins=["https://wp.example.com"])
        self.assertGreater(plan["summary"]["technology_template_count"], 0)
        p0 = plan["profiles"][0]
        has_wp = any(
            "wp" in t.get("template_id", "").lower()
            or "wordpress" in t.get("relative_path", "").lower()
            or any("wordpress" in tag for tag in t.get("tags", []))
            for t in p0["selected_templates"]
        )
        self.assertTrue(has_wp, "WordPress tech signal should select WordPress/PHP templates")

    def test_25_unrelated_technologies_do_not_select_templates(self):
        """2. unrelated technologies do not select templates (WordPress target has no IIS or Drupal)."""
        active_json = os.path.join(self.test_dir, "active_urls.json")
        with open(active_json, "w", encoding="utf-8") as f:
            f.write(json.dumps({"url": "https://wp.example.com", "tech": ["WordPress"]}) + "\n")

        plan = generate_nuclei_scan_plan(self.test_dir, origins=["https://wp.example.com"])
        p0 = plan["profiles"][0]
        tpl_ids = [t["template_id"].lower() for t in p0["selected_templates"]]
        for tid in tpl_ids:
            self.assertNotIn("drupal", tid)
            self.assertNotIn("joomla", tid)
            self.assertNotIn("aspnet", tid)

    def test_26_kiterunner_swagger_signal_selects_swagger_templates(self):
        """3. Kiterunner Swagger signal selects Swagger templates."""
        api_txt = os.path.join(self.test_dir, "api_endpoints.txt")
        with open(api_txt, "w", encoding="utf-8") as f:
            f.write("https://api.example.com/v2/swagger.json\n")

        plan = generate_nuclei_scan_plan(self.test_dir, origins=["https://api.example.com"])
        self.assertGreater(plan["summary"]["discovery_template_count"], 0)
        p0 = plan["profiles"][0]
        tpl_ids = [t["template_id"].lower() for t in p0["selected_templates"]]
        has_swagger = any("swagger" in tid or "openapi" in tid or "api" in tid for tid in tpl_ids)
        self.assertTrue(has_swagger, "Swagger route signal should select Swagger/OpenAPI templates")

    def test_27_graphql_signal_selects_graphql_templates(self):
        """4. GraphQL signal selects GraphQL templates."""
        api_txt = os.path.join(self.test_dir, "api_endpoints.txt")
        with open(api_txt, "w", encoding="utf-8") as f:
            f.write("https://api.example.com/graphql\n")

        plan = generate_nuclei_scan_plan(self.test_dir, origins=["https://api.example.com"])
        self.assertGreater(plan["summary"]["discovery_template_count"], 0)
        p0 = plan["profiles"][0]
        tpl_ids = [t["template_id"].lower() for t in p0["selected_templates"]]
        has_graphql = any("graphql" in tid for tid in tpl_ids)
        self.assertTrue(has_graphql, "GraphQL route signal should select GraphQL templates")

    def test_28_no_technology_still_selects_baseline(self):
        """5. no technology still selects universal safe baseline (never skips scanning)."""
        plan = generate_nuclei_scan_plan(self.test_dir, origins=["https://unknown-tech.example.com"])
        self.assertGreater(plan["summary"]["baseline_template_count"], 0)
        self.assertEqual(plan["summary"]["baseline_template_count"], 19)
        self.assertEqual(plan["summary"]["selected_template_count"], 19)

    def test_29_safe_manifest_is_mandatory(self):
        """6. Safe Manifest is mandatory: all selected templates must belong to Safe Manifest."""
        manifest_mgr = SafeManifestManager()
        safe_map = manifest_mgr.build_or_load_manifest()

        plan = generate_nuclei_scan_plan(self.test_dir, origins=["https://example.com"])
        for p in plan["profiles"]:
            for tpl in p["selected_templates"]:
                self.assertIn(tpl["template_id"], safe_map)

    def test_30_blocked_template_never_selected(self):
        """7. blocked template never selected (dos, fuzz, bruteforce, intrusive, local excluded)."""
        manifest_mgr = SafeManifestManager()
        safe_map = manifest_mgr.build_or_load_manifest()
        banned = {"dos", "fuzz", "bruteforce", "intrusive", "local"}

        for tpl_id, tpl in safe_map.items():
            tags = set(tpl.get("tags", []))
            self.assertTrue(tags.isdisjoint(banned), f"Template {tpl_id} contains banned tags: {tags & banned}")

    def test_31_review_template_never_selected_automatically(self):
        """8. review template never selected automatically (code, javascript, dast protocols excluded)."""
        manifest_mgr = SafeManifestManager()
        safe_map = manifest_mgr.build_or_load_manifest()
        banned_proto = {"code", "javascript", "headless", "dast", "file"}

        for tpl_id, tpl in safe_map.items():
            rel_p = tpl.get("relative_path", "").lower()
            for bp in banned_proto:
                self.assertNotIn(f"/{bp}/", f"/{rel_p}/")

    def test_32_template_score_ranking_works(self):
        """9. template score ranking works (confidence scoring ranks high confidence signals higher)."""
        active_records = [
            {
                "url": "https://api.example.com",
                "tech": ["WordPress:5.8.1", "Apache"],
                "webserver": "Apache/2.4.41",
                "title": "WordPress Admin Login"
            }
        ]
        signals = extract_origin_signals("https://api.example.com", active_records, ["https://api.example.com/wp-login.php"])
        self.assertGreater(signals["confidence_scores"].get("wordpress", 0), 100)
        self.assertGreater(signals["confidence_scores"].get("apache", 0), 60)

    def test_33_per_origin_template_budget_enforced(self):
        """10. per-origin template budget enforced (max 80 templates)."""
        active_json = os.path.join(self.test_dir, "active_urls.json")
        with open(active_json, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "url": "https://huge-stack.example.com",
                "tech": ["WordPress", "PHP", "Laravel", "Apache", "Nginx", "Jenkins", "Grafana", "Swagger"]
            }) + "\n")

        plan = generate_nuclei_scan_plan(self.test_dir, origins=["https://huge-stack.example.com"])
        p0 = plan["profiles"][0]
        self.assertLessEqual(len(p0["selected_templates"]), 80)
        self.assertLessEqual(p0["template_counts"]["total"], 80)

    def test_34_request_budget_enforced(self):
        """11. request budget enforced (max 500 estimated requests per origin)."""
        active_json = os.path.join(self.test_dir, "active_urls.json")
        with open(active_json, "w", encoding="utf-8") as f:
            f.write(json.dumps({"url": "https://app.example.com", "tech": ["WordPress", "PHP"]}) + "\n")

        plan = generate_nuclei_scan_plan(self.test_dir, origins=["https://app.example.com"])
        p0 = plan["profiles"][0]
        total_reqs = sum(t.get("estimated_requests", 1) for t in p0["selected_templates"])
        self.assertLessEqual(total_reqs, 500)

    def test_35_scan_wide_budget_enforced(self):
        """12. scan-wide budget enforced (max 3000 pairs, budget_limited flag set)."""
        dummy_origins = [f"https://sub{i}.example.com" for i in range(200)]
        plan = generate_nuclei_scan_plan(self.test_dir, origins=dummy_origins, scan_wide_pair_budget=3000)
        total_pairs = sum(len(p["origins"]) * len(p["selected_templates"]) for p in plan["profiles"])
        self.assertLessEqual(total_pairs, 3000)
        self.assertTrue(plan["summary"]["budget_limited"])

    def test_36_selection_reasons_recorded(self):
        """13. selection reasons recorded (explainability recorded in scan plan)."""
        active_json = os.path.join(self.test_dir, "active_urls.json")
        with open(active_json, "w", encoding="utf-8") as f:
            f.write(json.dumps({"url": "https://wp.example.com", "tech": ["WordPress"]}) + "\n")

        plan = generate_nuclei_scan_plan(self.test_dir, origins=["https://wp.example.com"])
        p0 = plan["profiles"][0]
        self.assertTrue(len(p0["explainability"]) > 0)
        first_exp = p0["explainability"][0]
        self.assertIn("template_id", first_exp)
        self.assertIn("layer", first_exp)
        self.assertIn("reasons", first_exp)

    def test_37_version_signal_does_not_fabricate_vulnerability(self):
        """14. version signal does not fabricate vulnerability (requires scanner match)."""
        active_json = os.path.join(self.test_dir, "active_urls.json")
        with open(active_json, "w", encoding="utf-8") as f:
            f.write(json.dumps({"url": "https://wp.example.com", "tech": ["WordPress:5.8.1"]}) + "\n")

        with patch("core.stage3_vulnerabilities.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, "")
            # Empty raw file simulated
            raw_file = os.path.join(self.test_dir, "nuclei_raw_profile-001.jsonl")
            with open(raw_file, "w", encoding="utf-8") as rf:
                pass

            ok, findings = run_nuclei(self.test_dir, self.scan_id)
            self.assertTrue(ok)
            # Even with vulnerable version in tech, zero fabricated findings without raw match!
            self.assertEqual(len(findings), 0)

    def test_38_cdn_analytics_tech_does_not_dominate_selection(self):
        """15. CDN/analytics technology does not dominate selection (classified as peripheral)."""
        self.assertEqual(classify_technology("Cloudflare")[1], "cdn")
        self.assertEqual(classify_technology("Google Analytics")[1], "analytics")
        self.assertEqual(classify_technology("Hotjar")[1], "analytics")

        active_json = os.path.join(self.test_dir, "active_urls.json")
        with open(active_json, "w", encoding="utf-8") as f:
            f.write(json.dumps({"url": "https://cdn-only.example.com", "tech": ["Cloudflare", "Google Analytics"]}) + "\n")

        plan = generate_nuclei_scan_plan(self.test_dir, origins=["https://cdn-only.example.com"])
        p0 = plan["profiles"][0]
        # Peripheral technologies do not trigger specialized Layer B templates
        self.assertEqual(p0["template_counts"]["technology_count"], 0)
        self.assertEqual(p0["template_counts"]["baseline_count"], 19)

    def test_39_profile_grouping_works(self):
        """16. profile grouping works (origins sharing identical template sets grouped into single profile)."""
        origins = ["https://site1.example.com", "https://site2.example.com", "https://site3.example.com"]
        plan = generate_nuclei_scan_plan(self.test_dir, origins=origins)
        # All 3 have identical unknown tech -> grouped into 1 profile
        self.assertEqual(len(plan["profiles"]), 1)
        self.assertEqual(len(plan["profiles"][0]["origins"]), 3)

    def test_40_duplicate_templates_removed(self):
        """17. duplicate templates removed (no duplicate template IDs within a profile)."""
        plan = generate_nuclei_scan_plan(self.test_dir, origins=["https://example.com"])
        for p in plan["profiles"]:
            tids = [t["template_id"] for t in p["selected_templates"]]
            self.assertEqual(len(tids), len(set(tids)), "Duplicate template IDs found in selected_templates!")

    def test_41_rate_limit_fixed_to_safe_default(self):
        """18. rate limit fixed to safe default (10 req/s)."""
        plan = generate_nuclei_scan_plan(self.test_dir, origins=["https://example.com"])
        self.assertEqual(plan["summary"]["rate_limit"], 10)
        for p in plan["profiles"]:
            self.assertEqual(p["limits"]["rate_limit"], 10)

    def test_42_concurrency_safe_default(self):
        """19. concurrency safe default (5 templates)."""
        plan = generate_nuclei_scan_plan(self.test_dir, origins=["https://example.com"])
        self.assertEqual(plan["summary"]["concurrency"], 5)
        for p in plan["profiles"]:
            self.assertEqual(p["limits"]["concurrency"], 5)

    def test_43_retries_limited(self):
        """20. retries limited (retries == 0 in execution arguments)."""
        self.assertIn("-retries", NUCLEI_SAFE_FLAGS)
        idx = NUCLEI_SAFE_FLAGS.index("-retries")
        self.assertEqual(NUCLEI_SAFE_FLAGS[idx + 1], "0")

    def test_44_circuit_breaker_429_triggers_backoff(self):
        """21. 429 triggers backoff & circuit breaker (5 consecutive 429s trips breaker)."""
        breaker = OriginCircuitBreaker("https://api.example.com", consecutive_threshold=5)
        for _ in range(4):
            self.assertFalse(breaker.record_response(429))
            self.assertFalse(breaker.is_tripped)

        tripped = breaker.record_response(429)
        self.assertTrue(tripped)
        self.assertTrue(breaker.is_tripped)
        self.assertEqual(breaker.trip_reason, "rate_limited")

    def test_45_circuit_breaker_repeated_timeouts(self):
        """22. repeated timeouts trigger circuit breaker (5 consecutive timeouts trips breaker)."""
        breaker = OriginCircuitBreaker("https://api.example.com", consecutive_threshold=5)
        for _ in range(4):
            self.assertFalse(breaker.record_timeout())
            self.assertFalse(breaker.is_tripped)

        tripped = breaker.record_timeout()
        self.assertTrue(tripped)
        self.assertTrue(breaker.is_tripped)
        self.assertEqual(breaker.trip_reason, "target_unstable_timeouts")

    def test_46_circuit_breaker_high_5xx_rate(self):
        """23. high 5xx rate triggers circuit breaker (>50% 5xx in window >= 10)."""
        breaker = OriginCircuitBreaker("https://api.example.com")
        # 4 successes, 6 errors -> 60% 5xx
        for _ in range(4):
            breaker.record_response(200)
        for _ in range(5):
            breaker.record_response(500)
        self.assertFalse(breaker.is_tripped)

        tripped = breaker.record_response(500)
        self.assertTrue(tripped)
        self.assertTrue(breaker.is_tripped)
        self.assertEqual(breaker.trip_reason, "target_unstable_5xx")

    def test_47_circuit_breaker_403_alone_does_not_trip(self):
        """24. 403 alone does not trigger DoS protection (403 is access control, not load/instability)."""
        breaker = OriginCircuitBreaker("https://api.example.com")
        for _ in range(15):
            tripped = breaker.record_response(403)
            self.assertFalse(tripped)
        self.assertFalse(breaker.is_tripped)
        self.assertIsNone(breaker.trip_reason)

    def test_48_zero_findings_remains_zero(self):
        """25. zero findings remains zero (clean empty result handled properly)."""
        tf = os.path.join(self.test_dir, "nuclei_targets.txt")
        with open(tf, "w", encoding="utf-8") as f:
            f.write("https://clean.example.com\n")

        with patch("core.stage3_vulnerabilities.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, "")
            raw_file = os.path.join(self.test_dir, "nuclei_raw_profile-001.jsonl")
            with open(raw_file, "w", encoding="utf-8") as rf:
                pass

            ok, findings = run_nuclei(self.test_dir, self.scan_id)
            self.assertTrue(ok)
            self.assertEqual(len(findings), 0)
            meta_path = os.path.join(self.test_dir, "nuclei_metadata.json")
            with open(meta_path, "r", encoding="utf-8") as mf:
                meta = json.load(mf)
            self.assertEqual(meta["finding_count"], 0)
            self.assertEqual(meta["status"], "completed")

    def test_49_docker_failure_remains_failure(self):
        """26. Docker failure remains failure with status 'failed' and zero native fallback."""
        tf = os.path.join(self.test_dir, "nuclei_targets.txt")
        with open(tf, "w", encoding="utf-8") as f:
            f.write("https://fail.example.com\n")

        with patch("core.stage3_vulnerabilities.run_docker_tool") as mock_dock:
            with patch("core.stage3_vulnerabilities.run_native_nuclei_fallback") as mock_fb:
                mock_dock.return_value = (False, "Container OOM / daemon crash")

                ok, findings = run_nuclei(self.test_dir, self.scan_id)
                self.assertFalse(ok)
                self.assertEqual(findings, [])
                mock_fb.assert_not_called()

                meta_path = os.path.join(self.test_dir, "nuclei_metadata.json")
                with open(meta_path, "r", encoding="utf-8") as mf:
                    meta = json.load(mf)
                self.assertEqual(meta["status"], "failed")
                self.assertIn("Container OOM", meta["error"])

    # --------------------------------------------------------------------------
    # 25 SPECIFIC TESTS FOR HARDENED POLICY, REQUEST COST, & LOAD CONTROLS
    # --------------------------------------------------------------------------
    def test_policy_01_post_method_classified_review(self):
        """P01: HTTP POST method template classified as 'review'."""
        yaml_content = """
id: test-post-probe
info:
  name: Test POST probe
  severity: low
http:
  - method: POST
    path:
      - "{{BaseURL}}/api/login"
"""
        res = classify_template_content(yaml_content, tpl_id="test-post-probe")
        self.assertEqual(res["policy"], "review")
        self.assertIn("POST", res["reason"])

    def test_policy_02_request_body_classified_review(self):
        """P02: Request body present template classified as 'review'."""
        yaml_content = """
id: test-body-probe
info:
  name: Test body probe
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    body: '{"username": "admin"}'
"""
        res = classify_template_content(yaml_content, tpl_id="test-body-probe")
        self.assertEqual(res["policy"], "review")
        self.assertIn("body", res["reason"].lower())

    def test_policy_03_payloads_generator_classified_review(self):
        """P03: Payloads generator present template classified as 'review'."""
        yaml_content = """
id: test-payloads-probe
info:
  name: Test payloads probe
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/{{item}}"
    payloads:
      item:
        - "admin"
        - "login"
"""
        res = classify_template_content(yaml_content, tpl_id="test-payloads-probe")
        self.assertEqual(res["policy"], "review")
        self.assertIn("payload", res["reason"].lower())

    def test_policy_04_flow_execution_classified_review(self):
        """P04: Multi-step flow execution classified as 'review'."""
        yaml_content = """
id: test-flow-probe
info:
  name: Test flow probe
  severity: high
flow: http(1) && http(2)
http:
  - method: GET
    path:
      - "{{BaseURL}}/step1"
"""
        res = classify_template_content(yaml_content, tpl_id="test-flow-probe")
        self.assertEqual(res["policy"], "review")
        self.assertIn("flow", res["reason"].lower())

    def test_policy_05_mutating_methods_classified_blocked(self):
        """P05: Mutating HTTP methods (PUT, PATCH, DELETE) classified as 'blocked'."""
        for method in ["PUT", "PATCH", "DELETE"]:
            yaml_content = f"""
id: test-{method.lower()}-mutating
info:
  name: Test mutating {method}
  severity: critical
http:
  - method: {method}
    path:
      - "{{BaseURL}}/resource/1"
"""
            res = classify_template_content(yaml_content, tpl_id=f"test-{method.lower()}")
            self.assertEqual(res["policy"], "blocked")
            self.assertIn(method, res["reason"])

    def test_policy_06_unsafe_true_classified_blocked(self):
        """P06: unsafe: true execution mode classified as 'blocked'."""
        yaml_content = """
id: test-unsafe-mode
info:
  name: Test unsafe mode
  severity: high
unsafe: true
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
"""
        res = classify_template_content(yaml_content, tpl_id="test-unsafe")
        self.assertEqual(res["policy"], "blocked")
        self.assertIn("unsafe", res["reason"].lower())

    def test_policy_07_race_true_classified_blocked(self):
        """P07: race: true condition test classified as 'blocked'."""
        yaml_content = """
id: test-race-condition
info:
  name: Test race condition
  severity: high
race: true
http:
  - method: GET
    path:
      - "{{BaseURL}}/coupon/apply"
"""
        res = classify_template_content(yaml_content, tpl_id="test-race")
        self.assertEqual(res["policy"], "blocked")
        self.assertIn("race", res["reason"].lower())

    def test_policy_08_rce_tag_classified_review_or_blocked(self):
        """P08: RCE attack probe tags classified as 'review'."""
        yaml_content = """
id: test-rce-check
info:
  name: Test RCE exploit check
  severity: critical
  tags: rce,cve,injection
http:
  - method: GET
    path:
      - "{{BaseURL}}/execute?cmd=id"
"""
        res = classify_template_content(yaml_content, tpl_id="test-rce")
        self.assertIn(res["policy"], ["review", "blocked"])
        self.assertIn("rce", res["reason"].lower())

    def test_policy_09_sqli_tag_classified_review(self):
        """P09: SQLi attack probe tags classified as 'review'."""
        yaml_content = """
id: test-sqli-check
info:
  name: Test SQL injection check
  severity: critical
  tags: sqli,injection
http:
  - method: GET
    path:
      - "{{BaseURL}}/search?id=1'"
"""
        res = classify_template_content(yaml_content, tpl_id="test-sqli")
        self.assertEqual(res["policy"], "review")
        self.assertIn("sqli", res["reason"].lower())

    def test_policy_10_ssrf_tag_classified_review(self):
        """P10: SSRF attack probe tags classified as 'review'."""
        yaml_content = """
id: test-ssrf-check
info:
  name: Test SSRF check
  severity: high
  tags: ssrf,oast
http:
  - method: GET
    path:
      - "{{BaseURL}}/fetch?url={{interactsh-url}}"
"""
        res = classify_template_content(yaml_content, tpl_id="test-ssrf")
        self.assertEqual(res["policy"], "review")
        self.assertTrue("ssrf" in res["reason"].lower() or "interactsh" in res["reason"].lower())

    def test_policy_11_path_traversal_lfi_classified_review(self):
        """P11: Path traversal / LFI tags classified as 'review'."""
        yaml_content = """
id: test-lfi-check
info:
  name: Test LFI check
  severity: high
  tags: lfi,traversal
http:
  - method: GET
    path:
      - "{{BaseURL}}/view?file=../../../../etc/passwd"
"""
        res = classify_template_content(yaml_content, tpl_id="test-lfi")
        self.assertEqual(res["policy"], "review")
        self.assertTrue("lfi" in res["reason"].lower() or "traversal" in res["reason"].lower())

    def test_policy_12_safe_get_template_classified_safe(self):
        """P12: Clean GET non-mutating passive check classified as 'safe'."""
        yaml_content = """
id: test-safe-version-check
info:
  name: Safe Software Version Check
  severity: info
  tags: exposure,tech
http:
  - method: GET
    path:
      - "{{BaseURL}}/version.txt"
    matchers:
      - type: word
        words:
          - "v1.2.3"
"""
        res = classify_template_content(yaml_content, tpl_id="test-safe-version")
        self.assertEqual(res["policy"], "safe")
        self.assertEqual(res["request_cost"], 1)

    def test_policy_13_safe_head_template_classified_safe(self):
        """P13: Clean HEAD non-mutating passive check classified as 'safe'."""
        yaml_content = """
id: test-safe-head-check
info:
  name: Safe Header Exposure Check
  severity: info
  tags: exposure
http:
  - method: HEAD
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        part: header
        words:
          - "X-Powered-By"
"""
        res = classify_template_content(yaml_content, tpl_id="test-safe-head")
        self.assertEqual(res["policy"], "safe")
        self.assertEqual(res["request_cost"], 1)

    def test_policy_14_status_only_matcher_classified_review(self):
        """P14: Status-only vulnerability matcher on high/critical severity classified as 'review'."""
        yaml_content = """
id: test-status-only-critical
info:
  name: Fake Critical with Status Only
  severity: critical
  tags: cve
http:
  - method: GET
    path:
      - "{{BaseURL}}/hidden-endpoint"
    matchers:
      - type: status
        status:
          - 200
"""
        res = classify_template_content(yaml_content, tpl_id="test-status-only")
        self.assertEqual(res["policy"], "review")
        self.assertIn("status-only", res["reason"].lower())

    def test_policy_15_manifest_invariant_holds(self):
        """P15: Invariant verification: total == safe_count + review_count + blocked_count."""
        mgr = SafeManifestManager(NUCLEI_TEMPLATES_OFFICIAL_DIR)
        manifest = mgr.build_or_load_manifest()
        stats = mgr.get_stats()
        safe_cnt = stats["safe_count"]
        review_cnt = stats["review_count"]
        blocked_cnt = stats["blocked_count"]
        total = stats.get("total_categorized") or stats.get("total") or (safe_cnt + review_cnt + blocked_cnt)
        self.assertEqual(total, safe_cnt + review_cnt + blocked_cnt)
        self.assertGreater(safe_cnt, 0)
        self.assertGreater(review_cnt, 0)
        self.assertGreater(blocked_cnt, 0)

    def test_policy_16_request_cost_single_path(self):
        """P16: Request cost for single path template equals 1."""
        yaml_content = """
http:
  - method: GET
    path:
      - "{{BaseURL}}/path1"
"""
        cost, desc = estimate_request_cost(yaml_content)
        self.assertEqual(cost, 1)

    def test_policy_17_request_cost_multi_path(self):
        """P17: Request cost for multi-path template equals count of paths (3 paths == 3)."""
        yaml_content = """
http:
  - method: GET
    path:
      - "{{BaseURL}}/path1"
      - "{{BaseURL}}/path2"
      - "{{BaseURL}}/path3"
"""
        cost, desc = estimate_request_cost(yaml_content)
        self.assertEqual(cost, 3)

    def test_policy_18_request_cost_multi_http_blocks(self):
        """P18: Request cost for multiple HTTP blocks correctly sums path counts (4 paths == 4)."""
        yaml_content = """
http:
  - method: GET
    path:
      - "{{BaseURL}}/b1/p1"
      - "{{BaseURL}}/b1/p2"
  - method: HEAD
    path:
      - "{{BaseURL}}/b2/p1"
      - "{{BaseURL}}/b2/p2"
"""
        cost, desc = estimate_request_cost(yaml_content)
        self.assertEqual(cost, 4)

    def test_policy_19_request_cost_raw_requests(self):
        """P19: Request cost for raw HTTP requests matches count of raw blocks."""
        yaml_content = """
http:
  - raw:
      - |
        GET /admin HTTP/1.1
        Host: {{Hostname}}
      - |
        GET /login HTTP/1.1
        Host: {{Hostname}}
"""
        cost, desc = estimate_request_cost(yaml_content)
        self.assertEqual(cost, 2)

    def test_policy_20_payload_multiplier_increases_cost(self):
        """P20: Payload list multiplier correctly scales request cost."""
        yaml_content = """
http:
  - method: GET
    path:
      - "{{BaseURL}}/{{item}}"
    payloads:
      item:
        - "p1"
        - "p2"
        - "p3"
        - "p4"
        - "p5"
"""
        cost, desc = estimate_request_cost(yaml_content)
        self.assertEqual(cost, 5)

    def test_policy_21_unknown_cost_never_enters_safe_default(self):
        """P21: Unknown or unbounded payload template has cost None and never enters safe default."""
        yaml_content = """
id: test-unbounded-wordlist
info:
  name: Fuzzing with unbounded external wordlist
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/{{word}}"
    payloads:
      word: fuzzing/large-wordlist.txt
"""
        cost, desc = estimate_request_cost(yaml_content)
        self.assertIsNone(cost)
        res = classify_template_content(yaml_content, tpl_id="test-unbounded")
        self.assertEqual(res["policy"], "review")

    def test_policy_22_request_budget_enforces_summed_cost(self):
        """P22: Request Budget strictly enforces sum(request_cost) <= 500 requests."""
        # Mock manifest manager with 200 safe templates each costing 5 requests
        mock_mgr = MagicMock()
        mock_manifest = {}
        for i in range(200):
            mock_manifest[f"tpl_{i:03d}"] = {
                "template_id": f"tpl_{i:03d}",
                "name": f"Template {i}",
                "relative_path": f"http/tech/tpl_{i:03d}.yaml",
                "container_path": f"/opt/nuclei-templates/http/tech/tpl_{i:03d}.yaml",
                "severity": "INFO",
                "policy": "safe",
                "methods": ["GET"],
                "request_cost": 5,
                "tags": ["apache"]
            }
        mock_mgr.build_or_load_manifest.return_value = mock_manifest

        selector = AdaptiveTemplateSelector(mock_mgr)
        origin_signals = {
            "origin": "https://api.example.com",
            "eligible_technologies": [{"name": "apache", "category": "web_server", "confidence_score": 100, "reasons": ["test"]}],
            "route_signals": {}
        }
        res = selector.select_templates_for_origin(origin_signals, tech_max=200, origin_template_budget=200, origin_request_budget=500)
        self.assertLessEqual(res["estimated_requests"], 500)
        self.assertEqual(res["estimated_requests"], len(res["selected_templates"]) * 5)
        self.assertEqual(len(res["selected_templates"]), 100)  # 100 * 5 = 500
        self.assertEqual(res["skipped_due_to_budget"], 100)

    def test_policy_23_budget_prioritizes_score_over_cost(self):
        """P23: When exceeding budget, candidates prioritized by efficiency (score / cost)."""
        mock_mgr = MagicMock()
        mock_manifest = {
            # High efficiency: score 100, cost 1 -> eff = 100
            "tpl_high_eff": {
                "template_id": "tpl_high_eff",
                "name": "High Efficiency",
                "relative_path": "http/tech/tpl_high.yaml",
                "container_path": "/opt/nuclei-templates/http/tech/tpl_high.yaml",
                "policy": "safe",
                "request_cost": 1,
                "tags": ["nginx"]
            },
            # Low efficiency: score 100, cost 20 -> eff = 5
            "tpl_low_eff": {
                "template_id": "tpl_low_eff",
                "name": "Low Efficiency",
                "relative_path": "http/tech/tpl_low.yaml",
                "container_path": "/opt/nuclei-templates/http/tech/tpl_low.yaml",
                "policy": "safe",
                "request_cost": 20,
                "tags": ["nginx"]
            }
        }
        mock_mgr.build_or_load_manifest.return_value = mock_manifest

        selector = AdaptiveTemplateSelector(mock_mgr)
        origin_signals = {
            "origin": "https://api.example.com",
            "eligible_technologies": [{"name": "nginx", "category": "web_server", "confidence_score": 100, "reasons": ["test"]}],
            "route_signals": {}
        }
        # Set budget to only allow 10 requests (high eff fits, low eff does not fit)
        res = selector.select_templates_for_origin(origin_signals, tech_max=10, origin_template_budget=10, origin_request_budget=10)
        selected_ids = [t["template_id"] for t in res["selected_templates"]]
        self.assertIn("tpl_high_eff", selected_ids)
        self.assertNotIn("tpl_low_eff", selected_ids)

    def test_policy_24_rate_limiting_and_concurrency_in_command(self):
        """P24: Real Nuclei command strictly contains -rl 10, -c 5, -bs 5, -timeout 5, -retries 0."""
        tf = os.path.join(self.test_dir, "nuclei_targets.txt")
        with open(tf, "w", encoding="utf-8") as f:
            f.write("https://api.example.com\n")

        with patch("core.stage3_vulnerabilities.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, "")
            run_nuclei(self.test_dir, self.scan_id)
            args = mock_dock.call_args[1]["args"]
            self.assertIn("-rl", args)
            rl_idx = args.index("-rl")
            self.assertEqual(args[rl_idx + 1], "10")
            self.assertIn("-c", args)
            c_idx = args.index("-c")
            self.assertEqual(args[c_idx + 1], "5")
            self.assertIn("-bs", args)
            bs_idx = args.index("-bs")
            self.assertEqual(args[bs_idx + 1], "5")
            self.assertIn("-timeout", args)
            to_idx = args.index("-timeout")
            self.assertEqual(args[to_idx + 1], "5")
            self.assertIn("-retries", args)
            ret_idx = args.index("-retries")
            self.assertEqual(args[ret_idx + 1], "0")

    def test_policy_25_circuit_breaker_telemetry_honest_disclosure(self):
        """P25: Circuit breaker telemetry honest disclosure: Option B (Preventive Load Controls)."""
        scan_plan = generate_nuclei_scan_plan(self.test_dir, origins=["https://api.example.com"])
        self.assertEqual(scan_plan["load_protection"], "preventive_controls")
        self.assertTrue(scan_plan["preventive_load_controls"])
        self.assertEqual(scan_plan["circuit_breaker_telemetry"], "requires_upstream_proxy")
        self.assertTrue(scan_plan["summary"]["preventive_load_controls"])


if __name__ == "__main__":
    unittest.main()
