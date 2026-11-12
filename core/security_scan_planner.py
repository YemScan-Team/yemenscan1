import os
import json
import hashlib
from typing import Dict, List, Set, Any, Optional, Tuple
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MATRIX_PATH = os.path.join(BASE_DIR, "scan_capability_matrix.json")
RUNTIME_MANIFEST_PATH = os.path.join(BASE_DIR, "nuclei_runtime_manifest.json")

from core.nuclei_template_selector import (
    generate_nuclei_scan_plan,
    extract_origin_signals,
    AdaptiveTemplateSelector,
    SafeManifestManager,
    RuntimeTemplateMissingError
)

WAPITI_SAFE_MODULES: List[str] = [
    "http_headers",
    "csp",
    "cookieflags",
    "information_disclosure",
    "stacktrace_disclosure",
    "https_redirect",
    "inconsistent_redirection",
    "unsecure_password"
]

WAPITI_DAST_LIGHT_MODULES: List[str] = [
    "csrf",
    "redirect"
]

WAPITI_VERIFIED_PASSIVE_MODULES: Set[str] = {
    "http_headers",
    "csp",
    "cookieflags",
    "information_disclosure",
    "stacktrace_disclosure",
    "https_redirect",
    "inconsistent_redirection",
    "unsecure_password"
}

def is_same_origin(seed_url: str, target_orig: str) -> bool:
    """Verifies that seed_url shares the exact same scheme, hostname, and port as target_orig."""
    try:
        p_seed = urlparse(seed_url)
        p_orig = urlparse(target_orig)
        seed_host = (p_seed.hostname or "").lower().rstrip(".")
        orig_host = (p_orig.hostname or "").lower().rstrip(".")
        if not seed_host or seed_host != orig_host:
            return False
        seed_scheme = (p_seed.scheme or "http").lower()
        orig_scheme = (p_orig.scheme or "http").lower()
        if seed_scheme != orig_scheme:
            return False
        seed_port = p_seed.port or (443 if seed_scheme == "https" else 80)
        orig_port = p_orig.port or (443 if orig_scheme == "https" else 80)
        return seed_port == orig_port
    except Exception:
        return False

class SecurityScanPlanner:
    """
    Unified Scan Intelligence & Security Scan Planner for YemenScan.
    Enforces:
      1. Coverage Ownership Matrix: strictly one primary scanner per capability family.
      2. No duplicate capability families: duplicate_capability_families == [].
      3. Strict sequential scanner coordination: max_active_security_scanners_per_origin = 1.
      4. Safe runtime template validation for Nuclei (only verified bundled templates).
      5. Safe baseline and crawler-driven DAST profile for Wapiti (excluding invasive attacks).
    """

    def __init__(self, matrix_path: Optional[str] = None):
        self.matrix_path = matrix_path or MATRIX_PATH
        self.matrix = self._load_matrix()

    def _load_matrix(self) -> Dict[str, Any]:
        if not os.path.exists(self.matrix_path):
            raise FileNotFoundError(f"Capability matrix file not found: {self.matrix_path}")
        with open(self.matrix_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def validate_capability_ownership(self) -> Tuple[bool, List[str]]:
        """
        Validates that every active capability family has strictly one primary scanner
        and that no duplicate capability ownership exists across scanners.
        """
        capabilities = self.matrix.get("capabilities", {})
        scanner_assignments: Dict[str, List[str]] = {}
        duplicates: List[str] = []

        for cap_name, details in capabilities.items():
            status = details.get("coverage_status", "covered_default")
            primary = details.get("primary", "none").lower()
            if status in ("covered_default", "covered_optional"):
                if not primary or primary == "none":
                    duplicates.append(f"Missing primary scanner for covered capability '{cap_name}'")
                    continue
                scanner_assignments.setdefault(cap_name, []).append(primary)
                if len(scanner_assignments[cap_name]) > 1:
                    duplicates.append(cap_name)

        return (len(duplicates) == 0, duplicates)

    def get_scanner_capabilities(self, scanner: str, profile: Optional[str] = None) -> List[str]:
        """Returns all capability families assigned as primary to the given scanner, optionally filtered by profile."""
        capabilities = self.matrix.get("capabilities", {})
        res = []
        for k, v in capabilities.items():
            if v.get("primary", "").lower() == scanner.lower():
                if profile is not None:
                    if v.get("profile") == profile:
                        res.append(k)
                else:
                    res.append(k)
        return res

    def generate_joint_scan_plan(
        self,
        session_dir: str,
        origins: List[str],
        active_urls_json: Optional[str] = None,
        api_endpoints_file: Optional[str] = None,
        scan_wide_pair_budget: int = 3000,
        wapiti_profile: str = "safe",
        verify_ssl: bool = True
    ) -> Dict[str, Any]:
        """
        Builds the unified, non-overlapping Joint Security Scan Plan
        generating joint_scan_plan.json, nuclei_scan_plan.json, and wapiti_scan_plan.json.
        """
        is_valid, duplicates = self.validate_capability_ownership()
        if not is_valid:
            raise ValueError(f"Capability ownership conflict detected: {duplicates}")

        if active_urls_json is None:
            active_urls_json = os.path.join(session_dir, "active_urls.json")
        if api_endpoints_file is None:
            api_endpoints_file = os.path.join(session_dir, "api_endpoints.txt")

        # 1. Load active endpoint records
        active_records: List[Dict[str, Any]] = []
        if os.path.exists(active_urls_json):
            try:
                with open(active_urls_json, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if line.strip():
                            try:
                                active_records.append(json.loads(line.strip()))
                            except Exception:
                                pass
            except Exception:
                pass

        # 2. Load API discovery routes
        api_routes: List[str] = []
        if os.path.exists(api_endpoints_file):
            try:
                with open(api_endpoints_file, "r", encoding="utf-8") as f:
                    api_routes = [l.strip() for l in f if l.strip()]
            except Exception:
                pass

        # 3. Generate Nuclei Plan (Adaptive, budgeted, safe runtime templates only)
        nuclei_plan = generate_nuclei_scan_plan(
            session_dir=session_dir,
            origins=origins,
            active_urls_json=active_urls_json,
            api_endpoints_file=api_endpoints_file,
            scan_wide_pair_budget=scan_wide_pair_budget
        )

        # 4. Generate Wapiti Plan
        # Extract discovery endpoints to seed Wapiti per target with same-origin validation
        seeds_by_origin: Dict[str, List[str]] = {}
        for r in api_routes:
            p = urlparse(r)
            if p.netloc:
                cand_orig = f"{p.scheme or 'http'}://{p.netloc}"
                for orig in origins:
                    if is_same_origin(r, orig):
                        seeds_by_origin.setdefault(orig, []).append(r)
            else:
                for o in origins:
                    full_seed = f"{o.rstrip('/')}/{r.lstrip('/')}"
                    if is_same_origin(full_seed, o):
                        seeds_by_origin.setdefault(o, []).append(full_seed)

        disabled_redundant = [
            item["module"] for item in self.matrix.get("wapiti_disabled_redundant_modules", [])
        ]
        excluded_review = self.matrix.get("wapiti_active_attack_modules_review", [])

        # Select modules according to profile
        if wapiti_profile == "dast_light":
            enabled_modules = list(WAPITI_DAST_LIGHT_MODULES)
        else:
            wapiti_profile = "safe"
            enabled_modules = list(WAPITI_SAFE_MODULES)

        wapiti_targets = []
        for orig in origins:
            raw_seeds = seeds_by_origin.get(orig, [])
            # Deduplicate and strictly validate same-origin; max 5 seeds per origin
            valid_seeds: List[str] = []
            for s in raw_seeds:
                if is_same_origin(s, orig) and s not in valid_seeds:
                    valid_seeds.append(s)
                if len(valid_seeds) >= 5:
                    break

            wapiti_targets.append({
                "origin": orig,
                "url": orig,
                "seed_urls": valid_seeds,
                "seed_count": len(valid_seeds)
            })

        wapiti_plan = {
            "tool": "wapiti",
            "version": "3.3.2",
            "build_variant": "yemscan-safe1",
            "patches": ["no-form-submission-safe-profile"],
            "docker_image": "yemscan/wapiti:3.3.2",
            "image_id": "sha256:611a8feb8521736d9b91a5776db861323b89ae401909683476c65f239f0dace1",
            "repository_digest": None,
            "profile": wapiti_profile,
            "crawl_policy": "read_only" if wapiti_profile == "safe" else "standard",
            "allowed_http_methods": ["GET", "HEAD"] if wapiti_profile == "safe" else ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            "form_submission_enabled": (wapiti_profile != "safe"),
            "execution_policy": {
                "max_active_security_scanners_per_origin": 1,
                "sequential_after": "nuclei"
            },
            "enabled_modules": enabled_modules,
            "disabled_redundant_modules": disabled_redundant,
            "excluded_review_modules": excluded_review,
            "configuration": {
                "scan_profile": "paranoid",
                "tasks": 2,
                "max_depth": 3,
                "max_scan_time_seconds": 120,
                "max_attack_time_seconds": 30,
                "max_parameters": 15,
                "max_links_per_page": 20,
                "max_files_per_dir": 20,
                "timeout_seconds": 5,
                "verify_ssl": 1 if verify_ssl else 0,
                "no_bugreport": True,
                "format": "json"
            },
            "targets": wapiti_targets,
            "summary": {
                "target_count": len(wapiti_targets),
                "enabled_module_count": len(enabled_modules),
                "disabled_redundant_count": len(disabled_redundant),
                "excluded_review_count": len(excluded_review),
                "total_seeds": sum(t["seed_count"] for t in wapiti_targets)
            }
        }

        # 5. Build Unified Joint Scan Plan
        nuclei_capabilities = self.get_scanner_capabilities("nuclei")
        wapiti_capabilities = self.get_scanner_capabilities("wapiti", profile=wapiti_profile)

        joint_plan = {
            "version": "1.1.0",
            "description": "Unified Pre-Scan Intelligence and Coordination Plan for YemenScan",
            "coordination_policy": {
                "max_active_security_scanners_per_origin": 1,
                "execution_order": ["nuclei", "wapiti"],
                "single_primary_scanner": True,
                "disallow_duplicate_families": True,
                "no_phantom_coverage": True
            },
            "duplicate_capability_families": [],
            "coverage_ownership": {
                "nuclei": {
                    "capabilities": nuclei_capabilities,
                    "count": len(nuclei_capabilities)
                },
                "wapiti": {
                    "capabilities": wapiti_capabilities,
                    "count": len(wapiti_capabilities)
                }
            },
            "scanners": {
                "nuclei": {
                    "tool": "nuclei",
                    "engine_version": "v3.11.1",
                    "selected_templates_count": nuclei_plan.get("summary", {}).get("selected_template_count", 0),
                    "estimated_requests": nuclei_plan.get("summary", {}).get("estimated_request_count", 0),
                    "rate_limit": nuclei_plan.get("summary", {}).get("rate_limit", 10),
                    "concurrency": nuclei_plan.get("summary", {}).get("concurrency", 5),
                    "profiles_count": nuclei_plan.get("summary", {}).get("profile_count", 0)
                },
                "wapiti": {
                    "tool": "wapiti",
                    "engine_version": "3.3.2",
                    "profile": wapiti_profile,
                    "enabled_modules": wapiti_plan["enabled_modules"],
                    "disabled_redundant_modules_count": len(disabled_redundant),
                    "excluded_review_modules_count": len(excluded_review),
                    "targets_count": len(wapiti_targets),
                    "limits": wapiti_plan["configuration"]
                }
            },
            "summary": {
                "origins_count": len(origins),
                "scanners_coordinated": ["nuclei", "wapiti"],
                "max_active_security_scanners_per_origin": 1,
                "sequential_execution": True,
                "duplicate_capability_families_count": 0
            },
            "nuclei_plan": nuclei_plan,
            "wapiti_plan": wapiti_plan
        }

        # Save all plans to session_dir
        joint_plan_file = os.path.join(session_dir, "joint_scan_plan.json")
        with open(joint_plan_file, "w", encoding="utf-8") as jf:
            json.dump(joint_plan, jf, ensure_ascii=False, indent=2)

        wapiti_plan_file = os.path.join(session_dir, "wapiti_scan_plan.json")
        with open(wapiti_plan_file, "w", encoding="utf-8") as wf:
            json.dump(wapiti_plan, wf, ensure_ascii=False, indent=2)

        return joint_plan
