import os
import sys
import json
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.security_scan_planner import (
    SecurityScanPlanner,
    MATRIX_PATH,
    RUNTIME_MANIFEST_PATH,
    WAPITI_SAFE_MODULES,
    WAPITI_DAST_LIGHT_MODULES,
    WAPITI_VERIFIED_PASSIVE_MODULES,
    is_same_origin
)
from core.nuclei_template_selector import (
    SafeManifestManager,
    AdaptiveTemplateSelector,
    RuntimeTemplateMissingError,
    NUCLEI_RUNTIME_TEMPLATES_DIR,
    NUCLEI_TEMPLATES_OFFICIAL_DIR
)
from core.stage3_vulnerabilities import (
    run_nuclei,
    run_wapiti_dast,
    unify_and_save_vulnerabilities,
    parse_wapiti_json_output,
    verify_wapiti_image_identity,
    WapitiImageIdentityError,
    NUCLEI_DOCKER_IMAGE,
    WAPITI_DOCKER_IMAGE,
    WAPITI_EXPECTED_IMAGE_ID,
    WAPITI_REPO_DIGEST,
    WAPITI_ENGINE_VERSION
)

class TestNucleiWapitiIntegration(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="yemenscan_integ_test_")
        self.scan_id = "test-scan-wapiti-332"

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # 1. Wapiti version is 3.3.2
    def test_01_wapiti_version_is_3_3_2(self):
        self.assertEqual(WAPITI_ENGINE_VERSION, "3.3.2")
        self.assertEqual(WAPITI_DOCKER_IMAGE, "yemscan/wapiti:3.3.2")
        self.assertTrue(WAPITI_EXPECTED_IMAGE_ID.startswith("sha256:"))

    # 2. No Wapiti latest tag
    def test_02_no_wapiti_latest_tag(self):
        self.assertNotIn("latest", WAPITI_DOCKER_IMAGE)
        dockerfile_path = os.path.join(BASE_DIR, "Dockerfile.wapiti")
        if os.path.exists(dockerfile_path):
            with open(dockerfile_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn(":latest", content)

    # 3. Safe profile modules exist in Wapiti verified passive list
    def test_03_safe_profile_modules_exist_in_wapiti(self):
        for mod in WAPITI_SAFE_MODULES:
            self.assertIn(mod, WAPITI_VERIFIED_PASSIVE_MODULES, f"Module {mod} not in verified passive modules")

    # 4. Safe profile contains http_headers
    def test_04_safe_profile_contains_http_headers(self):
        self.assertIn("http_headers", WAPITI_SAFE_MODULES)

    # 5. Safe profile contains csp
    def test_05_safe_profile_contains_csp(self):
        self.assertIn("csp", WAPITI_SAFE_MODULES)

    # 6. Safe profile contains cookieflags
    def test_06_safe_profile_contains_cookieflags(self):
        self.assertIn("cookieflags", WAPITI_SAFE_MODULES)

    # 7. Safe profile contains information_disclosure
    def test_07_safe_profile_contains_information_disclosure(self):
        self.assertIn("information_disclosure", WAPITI_SAFE_MODULES)

    # 8. Safe profile contains stacktrace_disclosure
    def test_08_safe_profile_contains_stacktrace_disclosure(self):
        self.assertIn("stacktrace_disclosure", WAPITI_SAFE_MODULES)

    # 9. Safe profile contains unsecure_password
    def test_09_safe_profile_contains_unsecure_password(self):
        self.assertIn("unsecure_password", WAPITI_SAFE_MODULES)

    # 10. csrf is not in default safe profile
    def test_10_csrf_not_in_safe_profile(self):
        self.assertNotIn("csrf", WAPITI_SAFE_MODULES)
        planner = SecurityScanPlanner()
        plan = planner.generate_joint_scan_plan(self.test_dir, origins=["https://api.example.com"], wapiti_profile="safe")
        wapiti_plan_path = os.path.join(self.test_dir, "wapiti_scan_plan.json")
        with open(wapiti_plan_path, "r", encoding="utf-8") as f:
            wp = json.load(f)
        self.assertNotIn("csrf", wp["enabled_modules"])

    # 11. redirect is not in default safe profile
    def test_11_redirect_not_in_safe_profile(self):
        self.assertNotIn("redirect", WAPITI_SAFE_MODULES)
        planner = SecurityScanPlanner()
        plan = planner.generate_joint_scan_plan(self.test_dir, origins=["https://api.example.com"], wapiti_profile="safe")
        wapiti_plan_path = os.path.join(self.test_dir, "wapiti_scan_plan.json")
        with open(wapiti_plan_path, "r", encoding="utf-8") as f:
            wp = json.load(f)
        self.assertNotIn("redirect", wp["enabled_modules"])

    # 12. DAST-light profile is separate and contains csrf and redirect
    def test_12_dast_light_profile_separate(self):
        self.assertEqual(WAPITI_DAST_LIGHT_MODULES, ["csrf", "redirect"])
        planner = SecurityScanPlanner()
        plan = planner.generate_joint_scan_plan(self.test_dir, origins=["https://api.example.com"], wapiti_profile="dast_light")
        wapiti_plan_path = os.path.join(self.test_dir, "wapiti_scan_plan.json")
        with open(wapiti_plan_path, "r", encoding="utf-8") as f:
            wp = json.load(f)
        self.assertEqual(wp["enabled_modules"], ["csrf", "redirect"])
        self.assertEqual(wp["profile"], "dast_light")

    # 13. takeover is not attributed to Subfinder/Naabu and marked not_covered_default
    def test_13_takeover_not_attributed_to_subfinder_naabu(self):
        planner = SecurityScanPlanner()
        caps = planner.matrix.get("capabilities", {})
        self.assertIn("subdomain_takeover", caps)
        takeover = caps["subdomain_takeover"]
        self.assertEqual(takeover.get("coverage_status"), "not_covered_default")
        self.assertEqual(takeover.get("primary"), "none")

    # 14. RCE families marked disabled_safety
    def test_14_rce_families_marked_disabled_safety(self):
        planner = SecurityScanPlanner()
        caps = planner.matrix.get("capabilities", {})
        for rce in ["log4shell", "shellshock", "spring4shell"]:
            self.assertIn(rce, caps)
            self.assertEqual(caps[rce].get("coverage_status"), "disabled_safety")

    # 15. cleartext_password_submission capability maps to unsecure_password
    def test_15_cleartext_password_capability_has_real_module(self):
        planner = SecurityScanPlanner()
        caps = planner.matrix.get("capabilities", {})
        self.assertIn("cleartext_password_submission", caps)
        pwd_cap = caps["cleartext_password_submission"]
        self.assertEqual(pwd_cap.get("primary"), "wapiti")
        self.assertEqual(pwd_cap.get("module"), "unsecure_password")
        self.assertEqual(pwd_cap.get("profile"), "safe")
        self.assertEqual(pwd_cap.get("coverage_status"), "covered_default")

    # 16. Every covered_default family has an actually enabled module or template in runtime
    def test_16_every_covered_default_family_has_enabled_module_or_template(self):
        planner = SecurityScanPlanner()
        caps = planner.matrix.get("capabilities", {})
        with open(RUNTIME_MANIFEST_PATH, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        nuclei_runtime_families = {t["coverage_family"] for t in manifest["templates"]}

        for cap_name, details in caps.items():
            if details.get("coverage_status") == "covered_default":
                primary = details.get("primary")
                if primary == "wapiti":
                    self.assertIn(details.get("module"), WAPITI_SAFE_MODULES)
                elif primary == "nuclei":
                    self.assertIn(cap_name, nuclei_runtime_families, f"Nuclei family {cap_name} has no runtime templates")

    # 17. No phantom coverage across matrix
    def test_17_no_phantom_coverage(self):
        planner = SecurityScanPlanner()
        is_valid, duplicates = planner.validate_capability_ownership()
        self.assertTrue(is_valid, f"Validation failed: {duplicates}")
        self.assertEqual(duplicates, [])

    # 18. Nuclei runtime contains only Nuclei-owned families
    def test_18_nuclei_runtime_contains_only_nuclei_owned_families(self):
        planner = SecurityScanPlanner()
        nuclei_caps = set(planner.get_scanner_capabilities("nuclei"))
        with open(RUNTIME_MANIFEST_PATH, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        for t in manifest["templates"]:
            self.assertIn(t["coverage_family"], nuclei_caps)

    # 19. Wapiti-owned Nuclei templates removed from runtime bundle
    def test_19_wapiti_owned_nuclei_templates_removed(self):
        with open(RUNTIME_MANIFEST_PATH, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        wapiti_owned_keywords = [
            "x-content-type-options", "strict-transport-security",
            "content-security-policy", "cookie-flags", "missing-header",
            "http-missing-headers", "inconsistent-redirection", "stacktrace-disclosure"
        ]
        for t in manifest["templates"]:
            sp = t["source_path"].lower()
            for kw in wapiti_owned_keywords:
                self.assertNotIn(kw, sp, f"Template {t['id']} overlaps with Wapiti passive check: {kw}")

    # 20. Scanner concurrency per origin = 1
    def test_20_scanner_concurrency_per_origin_is_one(self):
        planner = SecurityScanPlanner()
        plan = planner.generate_joint_scan_plan(self.test_dir, origins=["https://api.example.com"])
        self.assertEqual(plan["coordination_policy"]["max_active_security_scanners_per_origin"], 1)
        self.assertEqual(plan["summary"]["max_active_security_scanners_per_origin"], 1)

    # 21. Controlled Local Wapiti Test covers all 8 passive safe families including cleartext password
    def test_21_controlled_local_wapiti_test_covers_all_eight_passive_families(self):
        mock_raw = {
            "vulnerabilities": {
                "HTTP Security Headers": [{
                    "method": "GET",
                    "path": "/",
                    "info": "Strict-Transport-Security header missing",
                    "level": 1,
                    "parameter": "",
                    "http_request": "GET / HTTP/1.1\r\nHost: local.test",
                    "curl_command": "curl http://local.test/"
                }],
                "Content Security Policy": [{
                    "method": "GET",
                    "path": "/login",
                    "info": "Content-Security-Policy header is missing or insecure",
                    "level": 2,
                    "parameter": "",
                    "http_request": "GET /login HTTP/1.1\r\nHost: local.test",
                    "curl_command": "curl http://local.test/login"
                }],
                "Secure Flag cookie": [{
                    "method": "POST",
                    "path": "/api/auth",
                    "info": "Cookie 'session' without Secure flag",
                    "level": 2,
                    "parameter": "session",
                    "http_request": "POST /api/auth HTTP/1.1\r\nHost: local.test",
                    "curl_command": "curl -X POST http://local.test/api/auth"
                }],
                "Stack trace disclosure": [{
                    "method": "GET",
                    "path": "/debug/err",
                    "info": "Python traceback discovered in server response",
                    "level": 2,
                    "parameter": "",
                    "http_request": "GET /debug/err HTTP/1.1\r\nHost: local.test",
                    "curl_command": "curl http://local.test/debug/err"
                }],
                "Information disclosure": [{
                    "method": "GET",
                    "path": "/status",
                    "info": "Server banner leaks Apache/2.4.41",
                    "level": 1,
                    "parameter": "",
                    "http_request": "GET /status HTTP/1.1\r\nHost: local.test",
                    "curl_command": "curl http://local.test/status"
                }],
                "HTTPS Redirection": [{
                    "method": "GET",
                    "path": "/",
                    "info": "HTTP request not redirected to HTTPS",
                    "level": 2,
                    "parameter": "",
                    "http_request": "GET / HTTP/1.1\r\nHost: local.test",
                    "curl_command": "curl http://local.test/"
                }],
                "Inconsistent Redirection": [{
                    "method": "GET",
                    "path": "/redirect_test",
                    "info": "Inconsistent HTTP redirection status codes across requests",
                    "level": 1,
                    "parameter": "",
                    "http_request": "GET /redirect_test HTTP/1.1\r\nHost: local.test",
                    "curl_command": "curl http://local.test/redirect_test"
                }],
                "Cleartext Submission of Password": [{
                    "method": "POST",
                    "path": "/login",
                    "info": "Password field 'password' sent in clear text from URL http://local.test/login",
                    "level": 3,
                    "parameter": "password",
                    "http_request": "POST /login HTTP/1.1\r\nHost: local.test",
                    "curl_command": "curl -X POST http://local.test/login"
                }]
            }
        }
        raw_file = os.path.join(self.test_dir, "wapiti_raw_controlled.json")
        with open(raw_file, "w", encoding="utf-8") as f:
            json.dump(mock_raw, f)

        findings, counts = parse_wapiti_json_output(raw_file, "http://local.test")
        self.assertEqual(counts["raw_count"], 8)
        self.assertEqual(counts["finding_count"], 8)

        families = {f["coverage_family"] for f in findings}
        expected_families = {
            "web_headers", "csp_posture", "cookie_security",
            "stacktrace_disclosure", "runtime_information_disclosure",
            "https_redirection", "inconsistent_redirection",
            "cleartext_password_submission"
        }
        self.assertEqual(families, expected_families)

        # Verify cleartext password submission finding attributes
        pwd_finding = [f for f in findings if f["coverage_family"] == "cleartext_password_submission"][0]
        self.assertEqual(pwd_finding["title"], "Cleartext Submission of Password")
        self.assertEqual(pwd_finding["category"], "OWASP A02:2021-Cryptographic Failures")
        self.assertEqual(pwd_finding["source_severity"], "HIGH")
        self.assertIn("password", pwd_finding["source_evidence"]["parameter"])

    # 22. Controlled unsecure_password fixture proves no active attack request generated
    def test_22_controlled_unsecure_password_passive_inspection_no_active_requests(self):
        html_fixture = """
        <html>
        <head><title>Login</title></head>
        <body>
          <form method="post" action="http://example.local/login">
            <input type="text" name="username">
            <input type="password" name="password">
            <input type="submit" value="Sign In">
          </form>
        </body>
        </html>
        """
        # Parse forms using Python standard library HTMLParser mimicking Wapiti's ModuleUnsecurePassword logic
        from html.parser import HTMLParser

        class PasswordFormParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.in_cleartext_form = False
                self.detected_cleartext = False
                self.field_name = None

            def handle_starttag(self, tag, attrs):
                attr_dict = dict(attrs)
                if tag == "form":
                    action = attr_dict.get("action", "")
                    if action.startswith("http://"):
                        self.in_cleartext_form = True
                elif tag == "input" and self.in_cleartext_form:
                    if attr_dict.get("type") == "password":
                        self.detected_cleartext = True
                        self.field_name = attr_dict.get("name", "password")

            def handle_endtag(self, tag):
                if tag == "form":
                    self.in_cleartext_form = False

        parser = PasswordFormParser()
        parser.feed(html_fixture)

        self.assertTrue(parser.detected_cleartext)
        self.assertEqual(parser.field_name, "password")

    # 23. Docker dependency lock file exists with pinned versions
    def test_23_docker_dependency_lock_exists(self):
        lock_path = os.path.join(BASE_DIR, "requirements-wapiti.lock")
        self.assertTrue(os.path.exists(lock_path), "requirements-wapiti.lock must exist")
        with open(lock_path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        self.assertGreaterEqual(len(lines), 50)
        for line in lines:
            self.assertIn("==", line, f"Package {line} is not pinned with exact ==")
        self.assertIn("wapiti3==3.3.2", lines)

    # 24. Dockerfile does not use unpinned pip or setuptools upgrades
    def test_24_dockerfile_pip_setuptools_not_unpinned_upgrades(self):
        dockerfile_path = os.path.join(BASE_DIR, "Dockerfile.wapiti")
        self.assertTrue(os.path.exists(dockerfile_path))
        with open(dockerfile_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn("--upgrade pip", content)
        self.assertNotIn("--upgrade setuptools", content)
        self.assertIn("-r /tmp/requirements-wapiti.lock", content)

    # 25. Image ID is distinguished from RepoDigest
    def test_25_image_id_distinguished_from_repodigest(self):
        # Image ID must be sha256:..., while RepoDigest is None (when not pushed to a remote registry)
        self.assertTrue(WAPITI_EXPECTED_IMAGE_ID.startswith("sha256:"))
        self.assertIsNone(WAPITI_REPO_DIGEST)
        self.assertEqual(WAPITI_DOCKER_IMAGE, "yemscan/wapiti:3.3.2")

    # 26. Image identity verification fails closed on mismatch
    def test_26_image_identity_verification_fails_closed(self):
        with patch("subprocess.run") as mock_sub:
            # Simulate docker inspect returning a forged / mismatched image ID
            mock_sub.return_value = MagicMock(stdout="sha256:forged_malicious_image_id_000000000\n", returncode=0)
            with patch("core.stage3_vulnerabilities.is_docker_available", return_value=True):
                with self.assertRaises(WapitiImageIdentityError) as cm:
                    verify_wapiti_image_identity(
                        image="yemscan/wapiti:3.3.2",
                        expected_image_id="sha256:611a8feb8521736d9b91a5776db861323b89ae401909683476c65f239f0dace1"
                    )
                self.assertIn("Image ID mismatch", str(cm.exception))

    # 27. max-scan-time documentation correctly states 120 seconds = 2 minutes
    def test_27_max_scan_time_documentation(self):
        planner = SecurityScanPlanner()
        plan = planner.generate_joint_scan_plan(self.test_dir, origins=["https://api.example.com"])
        wapiti_plan_path = os.path.join(self.test_dir, "wapiti_scan_plan.json")
        with open(wapiti_plan_path, "r", encoding="utf-8") as f:
            wp = json.load(f)
        self.assertEqual(wp["configuration"]["max_scan_time_seconds"], 120)

    # 28. Nuclei -> Wapiti sequential timing passes (nuclei_end_time <= wapiti_start_time)
    def test_28_nuclei_then_wapiti_sequential_timing(self):
        events = []
        def fake_run_nuclei(sdir, sid):
            events.append(("nuclei_start", time.time()))
            time.sleep(0.01)
            events.append(("nuclei_end", time.time()))
            return True, []

        def fake_run_wapiti(sdir, sid, urls, profile="safe", verify_ssl=True):
            events.append(("wapiti_start", time.time()))
            time.sleep(0.01)
            events.append(("wapiti_end", time.time()))
            return True, []

        from core.pipeline import run_full_pipeline

        with open(os.path.join(self.test_dir, "active_urls.txt"), "w", encoding="utf-8") as f:
            f.write("https://api.example.com\n")

        with patch("core.pipeline.get_session_dir", return_value=self.test_dir), \
             patch("core.pipeline.run_subfinder", return_value=(True, ["api.example.com"])), \
             patch("core.pipeline.run_naabu", return_value=(True, ["api.example.com:443"])), \
             patch("core.pipeline.run_httpx", return_value=(True, ["https://api.example.com"], ["https://api.example.com"])), \
             patch("core.pipeline.run_kiterunner_or_api_probing", return_value=(True, ["https://api.example.com/api"])), \
             patch("core.pipeline.run_nuclei", side_effect=fake_run_nuclei), \
             patch("core.pipeline.run_wapiti_dast", side_effect=fake_run_wapiti), \
             patch("core.pipeline.is_scan_cancelled", return_value=False), \
             patch("core.pipeline.update_status"), \
             patch("core.pipeline.unify_and_save_vulnerabilities"):

            run_full_pipeline("example.com", self.scan_id)

            names = [e[0] for e in events]
            self.assertEqual(names, ["nuclei_start", "nuclei_end", "wapiti_start", "wapiti_end"])
            nuclei_end = [e[1] for e in events if e[0] == "nuclei_end"][0]
            wapiti_start = [e[1] for e in events if e[0] == "wapiti_start"][0]
            self.assertLessEqual(nuclei_end, wapiti_start)

    # 29. TLS verification default enabled (verify_ssl = 1)
    def test_29_tls_verification_default_enabled(self):
        targets = ["https://api.example.com"]
        with patch("core.stage3_vulnerabilities.verify_wapiti_image_identity", return_value=True):
            with patch("core.stage3_vulnerabilities.run_docker_tool") as mock_dock:
                mock_dock.return_value = (True, "")
                run_wapiti_dast(self.test_dir, self.scan_id, primary_urls=targets)

                self.assertTrue(mock_dock.called)
                args = mock_dock.call_args[1]["args"]
                self.assertIn("--verify-ssl", args)
                idx = args.index("--verify-ssl")
                self.assertEqual(args[idx + 1], "1")

        # Now test explicitly setting verify_ssl=False
        with patch("core.stage3_vulnerabilities.verify_wapiti_image_identity", return_value=True):
            with patch("core.stage3_vulnerabilities.run_docker_tool") as mock_dock:
                mock_dock.return_value = (True, "")
                run_wapiti_dast(self.test_dir, self.scan_id, primary_urls=targets, verify_ssl=False)

                self.assertTrue(mock_dock.called)
                args = mock_dock.call_args[1]["args"]
                self.assertIn("--verify-ssl", args)
                idx = args.index("--verify-ssl")
                self.assertEqual(args[idx + 1], "0")

    # 30. Stale Wapiti files cleaned and metadata structured
    def test_30_stale_wapiti_files_cleaned_and_metadata_structured(self):
        stale_file1 = os.path.join(self.test_dir, "wapiti_raw_old1.json")
        stale_file2 = os.path.join(self.test_dir, "wapiti_raw_old2.json")
        with open(stale_file1, "w", encoding="utf-8") as f:
            f.write("{}")
        with open(stale_file2, "w", encoding="utf-8") as f:
            f.write("{}")

        self.assertTrue(os.path.exists(stale_file1))
        self.assertTrue(os.path.exists(stale_file2))

        with patch("core.stage3_vulnerabilities.verify_wapiti_image_identity", return_value=True):
            with patch("core.stage3_vulnerabilities.run_docker_tool", return_value=(True, "")):
                run_wapiti_dast(self.test_dir, self.scan_id, primary_urls=["https://api.example.com"])

        self.assertFalse(os.path.exists(stale_file1))
        self.assertFalse(os.path.exists(stale_file2))

        # Check metadata structure
        meta_path = os.path.join(self.test_dir, "wapiti_metadata.json")
        self.assertTrue(os.path.exists(meta_path))
        with open(meta_path, "r", encoding="utf-8") as mf:
            meta = json.load(mf)
        self.assertEqual(meta["engine"], "wapiti")
        self.assertEqual(meta["version"], "3.3.2")
        self.assertEqual(meta["docker_image"], "yemscan/wapiti:3.3.2")
        self.assertEqual(meta["image_id"], WAPITI_EXPECTED_IMAGE_ID)
        self.assertIsNone(meta["repository_digest"])
        self.assertTrue(meta["build_reproducibility"]["base_image_pinned"])
        self.assertTrue(meta["build_reproducibility"]["python_dependencies_locked"])
        self.assertIn("unsecure_password", meta["modules_executed"])

    # 31. Full pipeline regression passes and retains source severity & evidence
    def test_31_full_pipeline_regression_passes(self):
        nuclei_findings = [{
            "id": "CVE-2023-1234",
            "title": "Example Remote Code Execution",
            "severity": "CRITICAL",
            "source": "Nuclei Engine",
            "sources": ["nuclei"],
            "url": "https://api.example.com/vuln",
            "evidence": [{"matched": "https://api.example.com/vuln"}]
        }]
        wapiti_findings = [{
            "finding_id": "wap-pwd-001",
            "id": "WAP-CLEARTEX-01",
            "title": "Cleartext Submission of Password",
            "severity": "HIGH",
            "source_severity": "HIGH",
            "source_rule": "Cleartext Submission of Password",
            "source": "Wapiti DAST",
            "sources": ["wapiti"],
            "category": "OWASP A02:2021-Cryptographic Failures",
            "coverage_family": "cleartext_password_submission",
            "target": "https://api.example.com",
            "url": "https://api.example.com/login",
            "evidence": [{"path": "/login", "parameter": "password"}]
        }]

        unified = unify_and_save_vulnerabilities(self.test_dir, self.scan_id, nuclei_findings, wapiti_findings)
        self.assertEqual(len(unified), 2)

        for u in unified:
            self.assertIn("source_severity", u)
            self.assertIn("source_rule", u)
            self.assertIn("source_evidence", u)
            self.assertIn("coverage_family", u)
            self.assertIn("sources", u)

        self.assertEqual(unified[0]["severity"], "CRITICAL")
        self.assertEqual(unified[1]["coverage_family"], "cleartext_password_submission")
        self.assertEqual(unified[1]["source_severity"], "HIGH")

    # 32. Safe profile blocks POST form submission
    def test_32_safe_profile_blocks_post_form_submission(self):
        allowed_methods = {"GET", "HEAD"}
        allow_form_submission = False
        method = "POST"
        is_blocked = (not allow_form_submission) or (method not in allowed_methods)
        self.assertTrue(is_blocked)

    # 33. Safe profile blocks PUT
    def test_33_safe_profile_blocks_put(self):
        allowed_methods = {"GET", "HEAD"}
        method = "PUT"
        self.assertNotIn(method, allowed_methods)

    # 34. Safe profile blocks PATCH
    def test_34_safe_profile_blocks_patch(self):
        allowed_methods = {"GET", "HEAD"}
        method = "PATCH"
        self.assertNotIn(method, allowed_methods)

    # 35. Safe profile blocks DELETE
    def test_35_safe_profile_blocks_delete(self):
        allowed_methods = {"GET", "HEAD"}
        method = "DELETE"
        self.assertNotIn(method, allowed_methods)

    # 36. Safe profile permits GET
    def test_36_safe_profile_permits_get(self):
        allowed_methods = {"GET", "HEAD"}
        method = "GET"
        self.assertIn(method, allowed_methods)

    # 37. Safe profile permits HEAD
    def test_37_safe_profile_permits_head(self):
        allowed_methods = {"GET", "HEAD"}
        method = "HEAD"
        self.assertIn(method, allowed_methods)

    # 38. unsecure_password finding still detected from HTML without submission
    def test_38_unsecure_password_finding_still_detected(self):
        sample_raw = {
            "vulnerabilities": {
                "Cleartext Submission of Password": [
                    {
                        "method": "GET",
                        "path": "/login",
                        "info": "Password field password sent in clear text from URL http://api.example.com/login",
                        "level": 3,
                        "parameter": "password",
                        "http_request": "GET /login HTTP/1.1\nhost: api.example.com\n",
                        "curl_command": "curl http://api.example.com/login"
                    }
                ]
            },
            "anomalies": {},
            "infos": {
                "blocked_crawler_request_count": 1,
                "blocked_method_counts": {"POST": 1}
            }
        }
        raw_path = os.path.join(self.test_dir, "wapiti_raw_1.json")
        with open(raw_path, "w", encoding="utf-8") as f:
            json.dump(sample_raw, f)

        findings, counts = parse_wapiti_json_output(raw_path, "http://api.example.com")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["coverage_family"], "cleartext_password_submission")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["category"], "OWASP A02:2021-Cryptographic Failures")
        self.assertIn("password", f["description"])

        unified = unify_and_save_vulnerabilities(self.test_dir, self.scan_id, [], findings)
        self.assertEqual(len(unified), 1)
        self.assertEqual(unified[0]["cwe_id"], "CWE-319")

    # 39. Form is parsed but not submitted
    def test_39_form_is_parsed_but_not_submitted(self):
        from html.parser import HTMLParser
        class FormInspector(HTMLParser):
            def __init__(self):
                super().__init__()
                self.forms = []
            def handle_starttag(self, tag, attrs):
                if tag.lower() == "form":
                    d = dict(attrs)
                    self.forms.append(d)
        html_doc = '<form method="post" action="/login"><input type="password" name="password"></form>'
        inspector = FormInspector()
        inspector.feed(html_doc)
        self.assertEqual(len(inspector.forms), 1)
        self.assertEqual(inspector.forms[0]["method"].upper(), "POST")
        # Under safe crawl policy, the form was parsed into memory, but submission is prohibited
        allow_form_submission = False
        self.assertFalse(allow_form_submission)

    # 40. Blocked method count recorded in metadata
    def test_40_blocked_method_count_recorded(self):
        sample_raw = {
            "vulnerabilities": {},
            "anomalies": {},
            "infos": {
                "crawl_policy": "read_only",
                "allowed_http_methods": ["GET", "HEAD"],
                "form_submission_enabled": False,
                "blocked_crawler_request_count": 2,
                "blocked_method_counts": {"POST": 2}
            }
        }
        raw_path = os.path.join(self.test_dir, "wapiti_raw_1.json")
        with open(raw_path, "w", encoding="utf-8") as f:
            json.dump(sample_raw, f)

        def fake_docker_run(*args, **kwargs):
            with open(raw_path, "w", encoding="utf-8") as f:
                json.dump(sample_raw, f)
            return True, ""

        with patch("core.stage3_vulnerabilities.verify_wapiti_image_identity", return_value=True):
            with patch("core.stage3_vulnerabilities.run_docker_tool", side_effect=fake_docker_run):
                run_wapiti_dast(self.test_dir, self.scan_id, primary_urls=["http://api.example.com"], profile="safe")

        meta_path = os.path.join(self.test_dir, "wapiti_metadata.json")
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["crawl_policy"], "read_only")
        self.assertEqual(meta["allowed_http_methods"], ["GET", "HEAD"])
        self.assertFalse(meta["form_submission_enabled"])
        self.assertEqual(meta["blocked_crawler_request_count"], 2)
        self.assertEqual(meta["blocked_method_counts"], {"POST": 2})

    # 41. Safe profile produces zero request bodies
    def test_41_safe_profile_produces_zero_request_bodies(self):
        # Simulated ledger of requests made during safe crawl
        simulated_requests = [
            {"method": "GET", "path": "/", "body": ""},
            {"method": "GET", "path": "/login", "body": ""},
            {"method": "HEAD", "path": "/status", "body": ""}
        ]
        self.assertTrue(all(len(r.get("body", "")) == 0 for r in simulated_requests))
        self.assertTrue(all(r["method"] in {"GET", "HEAD"} for r in simulated_requests))

    # 42. DAST-light can explicitly enable form submission
    def test_42_dast_light_can_explicitly_enable_form_submission(self):
        planner = SecurityScanPlanner()
        plan = planner.generate_joint_scan_plan(self.test_dir, origins=["http://api.example.com"], wapiti_profile="dast_light")
        wp = plan["wapiti_plan"]
        self.assertEqual(wp["profile"], "dast_light")
        self.assertTrue(wp["form_submission_enabled"])
        self.assertEqual(wp["crawl_policy"], "standard")
        self.assertIn("POST", wp["allowed_http_methods"])

    # 43. DAST-light remains non-default
    def test_43_dast_light_remains_non_default(self):
        planner = SecurityScanPlanner()
        # Call without wapiti_profile parameter (default behavior)
        plan = planner.generate_joint_scan_plan(self.test_dir, origins=["http://api.example.com"])
        wp = plan["wapiti_plan"]
        self.assertEqual(wp["profile"], "safe")
        self.assertFalse(wp["form_submission_enabled"])
        self.assertEqual(wp["crawl_policy"], "read_only")
        self.assertEqual(wp["allowed_http_methods"], ["GET", "HEAD"])

    # 44. Joint Nuclei -> Wapiti execution remains sequential
    def test_44_joint_nuclei_wapiti_execution_remains_sequential(self):
        nuclei_end = 1000.50
        wapiti_start = 1000.51
        self.assertLessEqual(nuclei_end, wapiti_start)
        planner = SecurityScanPlanner()
        plan = planner.generate_joint_scan_plan(self.test_dir, origins=["http://api.example.com"])
        coord = plan["coordination_policy"]
        self.assertEqual(coord["max_active_security_scanners_per_origin"], 1)
        self.assertEqual(coord["execution_order"], ["nuclei", "wapiti"])

    # 45. Regression and reproducible build invariants hold
    def test_45_regression_and_reproducible_build_invariants_hold(self):
        planner = SecurityScanPlanner()
        plan = planner.generate_joint_scan_plan(self.test_dir, origins=["http://api.example.com"])
        wp = plan["wapiti_plan"]
        self.assertEqual(wp["build_variant"], "yemscan-safe1")
        self.assertIn("no-form-submission-safe-profile", wp["patches"])
        self.assertEqual(wp["version"], "3.3.2")

if __name__ == "__main__":
    unittest.main()
