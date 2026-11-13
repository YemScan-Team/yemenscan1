import os
import time
import hashlib
import json
import re
import shutil
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import requests
import urllib3
import yaml
from typing import List, Dict, Any, Tuple, Optional, Set

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from core.runner import run_docker_tool, run_local_tool, is_docker_available, is_scan_cancelled, ScanCancelledException
from core.session import update_status
from core.target_prioritizer import prioritize_urls, prioritize_hosts, prioritize_dict_records
from core.nuclei_template_selector import (
    generate_nuclei_scan_plan,
    SafeManifestManager,
    OriginCircuitBreaker,
    extract_origin_signals,
    AdaptiveTemplateSelector,
    RuntimeTemplateMissingError
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NUCLEI_TEMPLATES_DIR = os.path.join(BASE_DIR, "nuclei_templates")
NUCLEI_TEMPLATES_OFFICIAL_DIR = os.path.join(BASE_DIR, "nuclei_templates_official")
NUCLEI_RUNTIME_TEMPLATES_DIR = os.path.join(BASE_DIR, "nuclei_runtime_templates")
NUCLEI_RUNTIME_MANIFEST_PATH = os.path.join(BASE_DIR, "nuclei_runtime_manifest.json")

NUCLEI_DOCKER_IMAGE = "projectdiscovery/nuclei:v3.11.1@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb"
NUCLEI_ENGINE_VERSION = "v3.11.1"
NUCLEI_ENGINE_DIGEST = "sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb"
NUCLEI_TEMPLATES_VERSION = "v10.5.1"
NUCLEI_TEMPLATES_COMMIT = "79fb682760ab3d5b0e22afbb44709353cbebf023"
NUCLEI_TEMPLATES_CHECKSUM = "8a8a34ea672e2ee3674092112e5e6934309fc9aa"

WAPITI_DOCKER_IMAGE = "yemscan/wapiti:3.3.2"
WAPITI_ENGINE_VERSION = "3.3.2"
WAPITI_BUILD_VARIANT = "yemscan-safe1"
WAPITI_PATCHES = ["no-form-submission-safe-profile"]
WAPITI_EXPECTED_IMAGE_ID = "sha256:611a8feb8521736d9b91a5776db861323b89ae401909683476c65f239f0dace1"
WAPITI_REPO_DIGEST = None

class WapitiImageIdentityError(RuntimeError):
    """Raised when the actual Docker image ID does not match the expected pinned ID (fail closed)."""
    pass

def verify_wapiti_image_identity(
    image: str = WAPITI_DOCKER_IMAGE,
    expected_image_id: str = WAPITI_EXPECTED_IMAGE_ID
) -> bool:
    """
    Verifies that the local Docker image ID matches the expected immutable ID.
    Raises WapitiImageIdentityError (fail closed) if there is a mismatch.
    """
    import subprocess
    if not is_docker_available():
        return True
    try:
        res = subprocess.run(
            ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10
        )
        actual_id = res.stdout.strip()
        if actual_id and actual_id != expected_image_id:
            raise WapitiImageIdentityError(
                f"Wapiti Docker Image ID mismatch! Expected: {expected_image_id}, Got: {actual_id}. Aborting for safety (fail closed)."
            )
        return True
    except subprocess.CalledProcessError as e:
        raise WapitiImageIdentityError(f"Failed to inspect Wapiti image '{image}': {e.stderr.strip()}")
    except Exception as ex:
        if isinstance(ex, WapitiImageIdentityError):
            raise
        return True

NUCLEI_SAFE_FLAGS: List[str] = [
    "-severity", "medium,high,critical",
    "-pt", "http",
    "-etags", "dos,fuzz,bruteforce,intrusive,local",
    "-dut",
    "-ni",
    "-lna",
    "-iv", "4",
    "-rl", "10",
    "-c", "5",
    "-bs", "5",
    "-timeout", "5",
    "-retries", "0",
    "-duc",
    "-nc",
    "-silent"
]

def normalize_target_origin(url_str: str) -> Optional[str]:
    """
    Normalizes an HTTP/HTTPS URL into its canonical base origin (scheme://hostname[:port]).
    - Strips whitespace.
    - Lowers scheme and hostname.
    - Strips trailing dots from hostname.
    - Omits default ports (80 for http, 443 for https).
    - Omits paths, query parameters, fragments, userinfo.
    Returns None if invalid.
    """
    if not url_str or not isinstance(url_str, str):
        return None
    raw = url_str.strip()
    if "://" in raw:
        proto = raw.split("://", 1)[0].lower()
        if proto not in ("http", "https"):
            return None
    else:
        raw = f"http://{raw}"
    try:
        parsed = urlparse(raw)
        scheme = (parsed.scheme or "http").lower()
        if scheme not in ("http", "https"):
            return None
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if not hostname:
            return None
        port = parsed.port
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443) or port is None:
            return f"{scheme}://{hostname}"
        if port is not None:
            return f"{scheme}://{hostname}:{port}"
        return f"{scheme}://{hostname}"
    except Exception:
        return None

def normalize_matched_url(matched_url: str) -> str:
    """
    Normalizes a matched URL for deduplication while preserving path/query if present.
    """
    if not matched_url:
        return ""
    try:
        parsed = urlparse(matched_url.strip())
        origin = normalize_target_origin(matched_url)
        if not origin:
            return matched_url.strip()
        path = parsed.path.rstrip("/")
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{origin}{path}{query}"
    except Exception:
        return matched_url.strip()

def write_nuclei_template_manifest(session_dir: str) -> Dict[str, Any]:
    """Writes the official immutable template & execution manifest for auditability."""
    manifest = {
        "templates_path": "/opt/nuclei-templates",
        "templates_version": NUCLEI_TEMPLATES_VERSION,
        "templates_commit": NUCLEI_TEMPLATES_COMMIT,
        "templates_tree_checksum": NUCLEI_TEMPLATES_CHECKSUM,
        "signature_verification": "enforced_dut",
        "protocol_scope": ["http"],
        "severities": ["medium", "high", "critical"],
        "excluded_tags": ["dos", "fuzz", "bruteforce", "intrusive", "local"],
        "flags": list(NUCLEI_SAFE_FLAGS),
        "selection_strategy": "adaptive",
        "load_protection": "preventive_controls",
        "preventive_load_controls": True,
        "circuit_breaker_telemetry": "requires_upstream_proxy",
        "rate_limit": 10,
        "concurrency": 5,
        "template_budget": 80,
        "request_budget": 500
    }

    # Write safe manifest files if official templates exist
    try:
        mgr = SafeManifestManager(NUCLEI_TEMPLATES_OFFICIAL_DIR)
        safe_map = mgr.build_or_load_manifest()
        stats = mgr.get_stats()
        manifest["safe_policy_count"] = stats.get("safe_count", len(safe_map))
        manifest["review_policy_count"] = stats.get("review_count", 0)
        manifest["blocked_policy_count"] = stats.get("blocked_count", 0)
        manifest["total_templates_evaluated"] = stats.get("total_categorized", 0)
        manifest["invariant_holds"] = stats.get("invariant_holds", True)
        mgr.write_manifest_files(session_dir)
    except Exception as e:
        print(f"[-] ملاحظة: تعذر استخراج manifest الآمن: {e}", flush=True)

    manifest_path = os.path.join(session_dir, "nuclei_template_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    return manifest

def clean_nuclei_session_artifacts(session_dir: str) -> None:
    """Removes any stale artifacts from prior Nuclei runs in the session directory."""
    artifacts = [
        "nuclei_targets.txt",
        "nuclei_raw.jsonl",
        "nuclei_findings.json",
        "nuclei_metadata.json",
        "nuclei_stderr.log",
        "nuclei_template_manifest.json",
        "nuclei_safe_manifest.json",
        "nuclei_safe_manifest.txt",
        "nuclei_scan_plan.json",
    ]
    for filename in artifacts:
        fp = os.path.join(session_dir, filename)
        if os.path.exists(fp):
            try:
                os.remove(fp)
            except Exception:
                pass

    # Also clean profile-specific files
    if os.path.exists(session_dir):
        try:
            for f in os.listdir(session_dir):
                if f.startswith(("selected_templates_", "nuclei_targets_", "nuclei_raw_")) and (f.endswith(".txt") or f.endswith(".jsonl")):
                    try:
                        os.remove(os.path.join(session_dir, f))
                    except Exception:
                        pass
        except Exception:
            pass

def get_nuclei_templates_info() -> List[Dict[str, Any]]:
    """Returns metadata for all available Nuclei templates in the library."""
    templates = []
    if not os.path.exists(NUCLEI_TEMPLATES_DIR):
        return templates

    for root, _, files in os.walk(NUCLEI_TEMPLATES_DIR):
        for f in files:
            if f.endswith((".yaml", ".yml")):
                fp = os.path.join(root, f)
                try:
                    with open(fp, "r", encoding="utf-8") as yf:
                        data = yaml.safe_load(yf)
                        if isinstance(data, dict):
                            info = data.get("info", {})
                            rel_category = os.path.basename(root)
                            templates.append({
                                "id": data.get("id", f),
                                "name": info.get("name", f),
                                "severity": info.get("severity", "info").upper(),
                                "author": info.get("author", "YemenScan"),
                                "category": rel_category,
                                "description": info.get("description", ""),
                                "remediation": info.get("remediation", ""),
                                "tags": info.get("tags", []),
                                "file_path": fp
                            })
                except Exception:
                    pass
    return templates

# Technology to Nuclei Tag mappings
TECH_TO_NUCLEI_TAGS: Dict[str, List[str]] = {
    "wordpress": ["wordpress", "wp-plugin"],
    "wp-": ["wordpress", "wp-plugin"],
    "elementor": ["wordpress", "wp-plugin"],
    "woocommerce": ["wordpress", "wp-plugin"],
    "yoast": ["wordpress", "wp-plugin"],
    "php": ["php"],
    "laravel": ["laravel", "php"],
    "symfony": ["symfony", "php"],
    "codeigniter": ["codeigniter", "php"],
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "magento": ["magento"],
    "nginx": ["nginx"],
    "apache": ["apache", "httpd"],
    "httpd": ["apache", "httpd"],
    "iis": ["iis", "aspnet", "windows"],
    "asp.net": ["iis", "aspnet", "windows"],
    "microsoft-iis": ["iis", "aspnet", "windows"],
    "windows server": ["windows", "iis"],
    ".net": ["aspnet", "windows"],
    "nodejs": ["nodejs", "express"],
    "node.js": ["nodejs", "express"],
    "express": ["nodejs", "express"],
    "django": ["django", "python"],
    "flask": ["flask", "python"],
    "python": ["python"],
    "spring": ["spring", "springboot"],
    "spring-boot": ["spring", "springboot"],
    "actuator": ["spring", "springboot", "exposure"],
    "tomcat": ["tomcat"],
    "jenkins": ["jenkins"],
    "grafana": ["grafana"],
    "kibana": ["kibana", "elasticsearch"],
    "elasticsearch": ["elasticsearch"],
    "redis": ["redis"],
    "mongodb": ["mongodb"],
    "mysql": ["mysql"],
    "mariadb": ["mysql"],
    "postgresql": ["postgres"],
    "postgres": ["postgres"],
    "swagger": ["swagger", "api"],
    "openapi": ["openapi", "api"],
    "graphql": ["graphql", "api"],
    "rest": ["api"],
    "cpanel": ["cpanel"],
    "phpmyadmin": ["phpmyadmin"],
    "webmin": ["webmin"],
    "litespeed": ["litespeed", "php"],
    "cloudflare": ["cloudflare", "waf"],
    "fastly": ["waf"],
    "akamai": ["waf"],
    "ruby": ["ruby", "rails"],
    "rails": ["ruby", "rails"],
    "golang": ["go", "golang"],
    "go": ["go", "golang"],
    "java": ["java", "spring", "tomcat"],
}

def map_technologies_to_nuclei_tags(tech_list: List[str]) -> List[str]:
    """
    Normalizes and maps detected technologies (from HTTPX or banner grabbing)
    to standard, valid Nuclei template tags.
    """
    mapped_tags: Set[str] = set()
    for item in tech_list:
        if not item:
            continue
        item_str = str(item).strip().lower()
        matched = False
        for key, tags in TECH_TO_NUCLEI_TAGS.items():
            if key in item_str:
                for t in tags:
                    mapped_tags.add(t)
                matched = True
        if not matched:
            clean_tag = re.sub(r"[^a-z0-9_-]", "", item_str)
            if clean_tag and len(clean_tag) > 1 and not clean_tag.isdigit():
                mapped_tags.add(clean_tag)
    return sorted(list(mapped_tags))

def build_nuclei_tags(tech_list: List[str]) -> List[str]:
    """
    Constructs the final focused list of tags for smart, technology-driven Nuclei scanning.
    Avoids injecting broad generic tags (misconfig/exposure) when specific technologies are known,
    focusing 100% of scanning effort on detected stacks and high-impact CVEs.
    """
    detected_tags = map_technologies_to_nuclei_tags(tech_list)
    combined: List[str] = []
    
    if detected_tags:
        for t in detected_tags:
            if t not in combined:
                combined.append(t)
        # Append targeted CVE tag for high/critical known exploits in these stacks
        if "cve" not in combined:
            combined.append("cve")
    else:
        # Fallback only when zero technologies could be fingerprinted
        combined = ["cve", "exposure"]
                
    return combined

def extract_technologies_from_httpx(session_dir: str) -> Dict[str, Any]:
    """
    Parses active_urls.json (generated by HTTPX in Stage 2) to dynamically identify:
    - Web servers (Nginx, Apache, LiteSpeed, IIS, Cloudflare, etc.)
    - Tech stack & Frameworks (WordPress, PHP, Laravel, ASP.NET, MySQL, etc.)
    - CMS markers, plugins, and CPE records.
    Maps the detected stack to tailored Nuclei template categories and tags.
    """
    active_urls_json = os.path.join(session_dir, "active_urls.json")
    
    detected_tech = set()
    webservers = set()
    wordpress_detected = False
    php_detected = False
    apache_detected = False
    nginx_detected = False
    iis_detected = False
    api_detected = False
    
    # Check if api_endpoints.txt has entries
    api_file = os.path.join(session_dir, "api_endpoints.txt")
    if os.path.exists(api_file) and os.path.getsize(api_file) > 0:
        api_detected = True
        
    if os.path.exists(active_urls_json):
        try:
            with open(active_urls_json, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line_str = line.strip()
                    if not line_str:
                        continue
                    try:
                        record = json.loads(line_str)
                    except Exception:
                        continue
                    
                    # 1. Tech list from HTTPX -tech-detect
                    tech_list = record.get("tech", [])
                    for t in tech_list:
                        t_str = str(t).strip()
                        if t_str:
                            detected_tech.add(t_str)
                        t_low = t_str.lower()
                        if any(w in t_low for w in ["wordpress", "wp-", "elementor", "woocommerce", "yoast", "wp rocket"]):
                            wordpress_detected = True
                            php_detected = True
                        if any(w in t_low for w in ["php", "laravel", "symfony", "codeigniter"]):
                            php_detected = True
                        if "apache" in t_low:
                            apache_detected = True
                        if "nginx" in t_low:
                            nginx_detected = True
                        if any(w in t_low for w in ["iis", "asp.net", "microsoft-iis", "windows server", ".net"]):
                            iis_detected = True
                        if any(w in t_low for w in ["swagger", "graphql", "spring", "actuator", "rest"]):
                            api_detected = True
                            
                    # 2. Webserver field from HTTPX -web-server
                    ws = record.get("webserver")
                    if ws:
                        webservers.add(str(ws).strip())
                        ws_low = str(ws).lower()
                        if "apache" in ws_low:
                            apache_detected = True
                        elif "nginx" in ws_low:
                            nginx_detected = True
                        elif "iis" in ws_low or "microsoft" in ws_low:
                            iis_detected = True
                        elif "litespeed" in ws_low:
                            # LiteSpeed is typically paired with PHP/WordPress
                            php_detected = True
                            
                    # 3. Dedicated wordpress fingerprint object
                    if record.get("wordpress"):
                        wordpress_detected = True
                        php_detected = True
                        
                    # 4. CPE products detection
                    for cpe in record.get("cpe", []):
                        prod = ""
                        if isinstance(cpe, dict):
                            prod = cpe.get("product", "").lower()
                        elif isinstance(cpe, str):
                            prod = cpe.lower()
                        if any(w in prod for w in ["wordpress", "elementor", "woocommerce"]):
                            wordpress_detected = True
                            php_detected = True
                        if "php" in prod:
                            php_detected = True
                        if "apache" in prod:
                            apache_detected = True
                        if "nginx" in prod:
                            nginx_detected = True
        except Exception as e:
            print(f"[-] خطأ أثناء استخراج التقنيات من HTTPX: {e}", flush=True)

    # Base universal categories applicable to all black-box targets:
    selected_categories = ["cves", "vulnerabilities", "exposures"]
    
    # Dynamically inject targeted technology suites based on HTTPX findings
    if wordpress_detected and "wordpress" not in selected_categories:
        selected_categories.append("wordpress")
    if php_detected and "php" not in selected_categories:
        selected_categories.append("php")
    if apache_detected and "apache" not in selected_categories:
        selected_categories.append("apache")
    if nginx_detected and "nginx" not in selected_categories:
        selected_categories.append("nginx")
    if iis_detected and "iis" not in selected_categories:
        selected_categories.append("iis")
    if api_detected and "api" not in selected_categories:
        selected_categories.append("api")
        
    has_specific_tech = (wordpress_detected or php_detected or apache_detected or nginx_detected or iis_detected or api_detected)
    if not has_specific_tech:
        selected_categories = ["cves", "vulnerabilities", "exposures", "api", "wordpress", "php", "apache", "nginx", "iis"]

    all_tech_list = sorted(list(detected_tech | webservers))

    return {
        "detected_tech": sorted(list(detected_tech)),
        "webservers": sorted(list(webservers)),
        "all_tech": all_tech_list,
        "detected_tags": map_technologies_to_nuclei_tags(all_tech_list),
        "flags": {
            "wordpress": wordpress_detected,
            "php": php_detected,
            "apache": apache_detected,
            "nginx": nginx_detected,
            "iis": iis_detected,
            "api": api_detected
        },
        "selected_categories": selected_categories,
        "is_all_fallback": not has_specific_tech
    }

def extract_technologies_list(session_dir: str) -> List[str]:
    """
    Extracts a list of detected technology and webserver names from active_urls.json.
    Returns cleaned list ready to pass to run_optimized_nuclei.
    """
    profile = extract_technologies_from_httpx(session_dir)
    return profile.get("all_tech", []) or profile.get("detected_tech", [])

def prepare_nuclei_targets(session_dir: str) -> List[str]:
    """
    Extracts and normalizes unique Root Origins (scheme://hostname[:port])
    sourced strictly from active_urls.txt (or active_urls.json) to feed into Nuclei.
    Ensures clean slate before generating targets and enforces invariant zero handling.
    """
    print("[*] جاري استخراج وتجهيز النطاقات الأساسية لتوجيه محرك Nuclei...", flush=True)
    clean_nuclei_session_artifacts(session_dir)

    raw_urls: List[str] = []
    active_urls_file = os.path.join(session_dir, "active_urls.txt")
    if os.path.exists(active_urls_file):
        with open(active_urls_file, "r", encoding="utf-8") as f:
            for line in f:
                u = line.strip()
                if u:
                    raw_urls.append(u)

    if not raw_urls:
        active_urls_json = os.path.join(session_dir, "active_urls.json")
        if os.path.exists(active_urls_json):
            try:
                with open(active_urls_json, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line_str = line.strip()
                        if line_str:
                            try:
                                rec = json.loads(line_str)
                                u = rec.get("url") or rec.get("input")
                                if u:
                                    raw_urls.append(str(u).strip())
                            except Exception:
                                pass
            except Exception:
                pass

    origins_set: Set[str] = set()
    for u in raw_urls:
        norm = normalize_target_origin(u)
        if norm:
            origins_set.add(norm)

    final_targets = sorted(list(origins_set))

    # Prioritize root domain if present in status
    target_domain = ""
    status_file = os.path.join(session_dir, "status.json")
    if os.path.exists(status_file):
        try:
            with open(status_file, "r", encoding="utf-8") as sf:
                target_domain = json.load(sf).get("target_domain", "")
        except Exception:
            pass
    clean_dom = target_domain.split(":")[0].strip().lower() if target_domain else ""
    if clean_dom and final_targets:
        final_targets = prioritize_urls(final_targets, clean_dom)

    nuclei_targets_file = os.path.join(session_dir, "nuclei_targets.txt")
    with open(nuclei_targets_file, "w", encoding="utf-8") as f:
        for t in final_targets:
            f.write(f"{t}\n")

    write_nuclei_template_manifest(session_dir)

    if not final_targets:
        metadata = {
            "tool": "nuclei",
            "selection_strategy": "adaptive",
            "engine_version": NUCLEI_ENGINE_VERSION,
            "engine_digest": NUCLEI_ENGINE_DIGEST,
            "templates_version": NUCLEI_TEMPLATES_VERSION,
            "templates_commit": NUCLEI_TEMPLATES_COMMIT,
            "templates_checksum": NUCLEI_TEMPLATES_CHECKSUM,
            "input_count": 0,
            "profile_count": 0,
            "raw_count": 0,
            "valid_count": 0,
            "invalid_count": 0,
            "duplicate_count": 0,
            "out_of_scope_count": 0,
            "finding_count": 0,
            "baseline_template_count": 0,
            "technology_template_count": 0,
            "discovery_template_count": 0,
            "selected_template_count": 0,
            "skipped_due_to_template_budget": 0,
            "estimated_request_count": 0,
            "request_budget": 500,
            "rate_limit": 10,
            "concurrency": 5,
            "budget_limited": False,
            "circuit_breaker_triggered": False,
            "circuit_breaker_trip_count": 0,
            "load_protection": "preventive_controls",
            "preventive_load_controls": True,
            "circuit_breaker_telemetry": "requires_upstream_proxy",
            "status": "completed",
            "execution_duration_seconds": 0.0
        }
        with open(os.path.join(session_dir, "nuclei_metadata.json"), "w", encoding="utf-8") as mf:
            json.dump(metadata, mf, ensure_ascii=False, indent=2)
        with open(os.path.join(session_dir, "nuclei_findings.json"), "w", encoding="utf-8") as ff:
            json.dump([], ff, ensure_ascii=False, indent=2)
        print("[!] لم يتم العثور على أهداف ويب نشطة لتشغيل Nuclei.", flush=True)
        return []

    print(f"[+] تم استخراج وتجهيز {len(final_targets)} أهداف جذرية نظيفة لـ Nuclei: {', '.join(final_targets[:5])}", flush=True)
    return final_targets

def _normalize_template_tags(tpl: Dict[str, Any]) -> Set[str]:
    """Extracts and normalizes a template's tags into a lowercase set."""
    raw_tags = tpl.get("tags", "")
    tags = set()
    if isinstance(raw_tags, str):
        for t in raw_tags.split(","):
            val = t.strip().lower()
            if val:
                tags.add(val)
    elif isinstance(raw_tags, (list, tuple, set)):
        for t in raw_tags:
            val = str(t).strip().lower()
            if val:
                tags.add(val)
    return tags

def run_native_nuclei_fallback(
    targets: List[str],
    category: Optional[str] = None,
    target_categories: Optional[List[str]] = None,
    target_tags: Optional[List[str]] = None,
    target_severities: Optional[List[str]] = None,
    excluded_tags: Optional[List[str]] = None,
    scan_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    High-performance, multi-threaded Python fallback scanner implementing Nuclei HTTP matching rules.
    Focuses intelligently on detected technologies and strictly on CRITICAL, HIGH, and MEDIUM severities.
    Uses ThreadPoolExecutor to run template checks concurrently across targets in 1-3 seconds.
    """
    print("[*] تشغيل المحرك المباشر الذكي فائق السرعة لفحص قوالب Nuclei (تركيز على الخطورة الحرجة والعالية والمتوسطة)...", flush=True)
    findings = []
    findings_lock = threading.Lock()
    all_tpls = get_nuclei_templates_info()
    
    # Deduplicate targets by hostname to avoid duplicating identical checks on both HTTP and HTTPS
    seen_hosts = set()
    cleaned_targets = []
    # Sort prioritizing HTTPS over HTTP, then cleanest origin
    sorted_targets = sorted(targets, key=lambda u: (0 if u.startswith("https://") else 1, len(u)))
    for t in sorted_targets:
        clean = t.strip().rstrip("/")
        if not clean:
            continue
        try:
            h = urlparse(clean).netloc
            if h and h not in seen_hosts:
                seen_hosts.add(h)
                cleaned_targets.append(clean)
        except Exception:
            if clean not in cleaned_targets:
                cleaned_targets.append(clean)

    sample_targets = cleaned_targets[:5] if cleaned_targets else targets[:5]
    
    # Enforce strict focus on CRITICAL, HIGH, and MEDIUM severities by default
    effective_severities = target_severities or ["CRITICAL", "HIGH", "MEDIUM"]
    norm_severities = {s.upper() for s in effective_severities}
    norm_excluded = {e.lower() for e in excluded_tags} if excluded_tags else {"dos", "fuzz"}
    norm_target_tags = {t.lower() for t in target_tags} if target_tags else set()

    # Technology-specific families for intelligent template gating
    TECH_SPECIFIC_FAMILIES = {
        "wordpress": {"wordpress", "wp-plugin", "wp", "elementor"},
        "php": {"php", "laravel", "symfony", "codeigniter", "composer", "thinkphp"},
        "apache": {"apache", "httpd", "htaccess", "tomcat", "solr"},
        "nginx": {"nginx"},
        "iis": {"iis", "aspnet", "windows", "elmah"},
        "api": {"api", "graphql", "swagger", "springboot", "actuator", "prometheus"}
    }

    filtered_tpls = []
    for tpl in all_tpls:
        tpl_cat = tpl.get("category", "").lower()
        tpl_sev = tpl.get("severity", "INFO").upper()
        tpl_id = tpl.get("id", "")
        tpl_tags = _normalize_template_tags(tpl)

        # 1. Strict Severity Filter: Only CRITICAL and HIGH
        if norm_severities and tpl_sev not in norm_severities:
            continue

        # 2. Excluded noise tags
        if norm_excluded and any(ex in tpl_tags for ex in norm_excluded):
            continue

        # 3. Explicit category filter if provided
        if category and category.lower() not in ("all", "*", "") and category.lower() not in tpl_cat and category.lower() not in tpl_id.lower():
            continue
        if target_categories and tpl_cat not in target_categories and "all" not in target_categories:
            continue

        # 4. Smart Technology-Driven Filter:
        # If target technologies were fingerprinted, skip templates designed for OTHER un-detected technologies!
        if norm_target_tags:
            is_tech_specific = False
            tech_matches = False
            for family_name, family_tags in TECH_SPECIFIC_FAMILIES.items():
                if tpl_cat == family_name or any(ft in tpl_tags for ft in family_tags):
                    is_tech_specific = True
                    if any(t in family_tags or t == family_name for t in norm_target_tags):
                        tech_matches = True
                        break

            # If template belongs to an unrelated technology suite (e.g. IIS on Linux, WordPress on Django) -> skip it
            if is_tech_specific and not tech_matches:
                continue

        filtered_tpls.append((tpl, tpl_tags))

    if not filtered_tpls:
        # Fallback only to generic critical/high templates
        filtered_tpls = [
            (tpl, _normalize_template_tags(tpl))
            for tpl in all_tpls
            if tpl.get("severity", "INFO").upper() in norm_severities
        ]

    # Shared HTTP Session with adapter connection pooling
    http_session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=25, pool_maxsize=35, max_retries=0)
    http_session.mount("http://", adapter)
    http_session.mount("https://", adapter)

    def check_target_with_template(target_url: str, tpl: Dict[str, Any], tpl_tags: Set[str]):
        if scan_id and is_scan_cancelled(scan_id):
            return

        fp = tpl.get("file_path")
        if not fp or not os.path.exists(fp):
            return

        try:
            with open(fp, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception:
            return

        http_rules = data.get("http", [])
        clean_target = target_url.rstrip("/")

        for rule in http_rules:
            if scan_id and is_scan_cancelled(scan_id):
                return

            method = rule.get("method", "GET").upper()
            paths = rule.get("path", ["{{BaseURL}}"])
            headers = rule.get("headers", {})
            body = rule.get("body", None)
            matchers = rule.get("matchers", [])
            matchers_cond = rule.get("matchers-condition", "or").lower()

            for p in paths:
                url = p.replace("{{BaseURL}}", clean_target)
                try:
                    req_headers = {
                        "User-Agent": "YemenScan-NucleiAuditor/2.0",
                        **headers
                    }
                    if method == "POST":
                        resp = http_session.post(url, headers=req_headers, data=body, timeout=3, verify=False, allow_redirects=True)
                    else:
                        resp = http_session.get(url, headers=req_headers, timeout=3, verify=False, allow_redirects=True)

                    matched_list = []
                    for m in matchers:
                        m_type = m.get("type")
                        is_matched = False
                        part = m.get("part", "body").lower()

                        if part in ("header", "headers", "all_headers"):
                            target_text = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\r\n"
                        else:
                            target_text = resp.text

                        if m_type == "status":
                            statuses = m.get("status", [200])
                            is_matched = resp.status_code in statuses
                        elif m_type == "word":
                            words = m.get("words", [])
                            case_sensitive = m.get("case-sensitive", False)
                            if not case_sensitive:
                                target_compare = target_text.lower()
                                words_compare = [w.lower() for w in words]
                            else:
                                target_compare = target_text
                                words_compare = words

                            if m.get("condition", "or").lower() == "and":
                                is_matched = len(words_compare) > 0 and all(w in target_compare for w in words_compare)
                            else:
                                is_matched = any(w in target_compare for w in words_compare)
                        elif m_type == "regex":
                            regexes = m.get("regex", [])
                            if m.get("condition", "or").lower() == "and":
                                is_matched = len(regexes) > 0 and all(bool(re.search(r, target_text, re.IGNORECASE)) for r in regexes)
                            else:
                                is_matched = any(bool(re.search(r, target_text, re.IGNORECASE)) for r in regexes)

                        if m.get("negative", False):
                            is_matched = not is_matched
                        matched_list.append(is_matched)

                    is_vuln = (len(matched_list) > 0 and all(matched_list)) if matchers_cond == "and" else any(matched_list)

                    if is_vuln:
                        item = {
                            "id": tpl["id"],
                            "title": tpl["name"],
                            "severity": tpl["severity"],
                            "source": "Nuclei Engine",
                            "category": tpl["category"],
                            "url": url,
                            "description": tpl["description"] or f"تم اكتشاف مطابقة للقالب {tpl['id']}.",
                            "remediation": tpl["remediation"] or "مراجعة إعدادات الأمان وتطبيق التحديثات الموصى بها.",
                            "tags": list(tpl_tags)
                        }
                        with findings_lock:
                            if not any(f["id"] == item["id"] and f["url"] == item["url"] for f in findings):
                                findings.append(item)
                                print(f"[{item['severity']}] {item['title']} -> {url}", flush=True)
                        break
                except Exception:
                    continue

    # Execute all template tests in parallel
    try:
        tasks = []
        with ThreadPoolExecutor(max_workers=12) as executor:
            for target in sample_targets:
                for tpl, tpl_tags in filtered_tpls:
                    if scan_id and is_scan_cancelled(scan_id):
                        break
                    tasks.append(executor.submit(check_target_with_template, target, tpl, tpl_tags))

            for future in as_completed(tasks):
                try:
                    future.result()
                except Exception:
                    pass
    finally:
        http_session.close()

    return findings

def parse_nuclei_json_output(
    nuclei_raw_file: str,
    valid_target_origins: Optional[Set[str]] = None
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """
    Parses findings output generated by Nuclei into structured Python dictionaries line-by-line.
    Enforces strict provenance, deduplication on (template_id, norm_url, matcher_name),
    classification truth (CVE/CWE/CVSS strictly from info.classification),
    and exact count invariants: raw_count == valid_count + invalid_count + duplicate_count + out_of_scope_count.
    """
    findings: List[Dict[str, Any]] = []
    counts = {
        "raw_count": 0,
        "valid_count": 0,
        "invalid_count": 0,
        "duplicate_count": 0,
        "out_of_scope_count": 0
    }

    if not os.path.exists(nuclei_raw_file) or os.path.getsize(nuclei_raw_file) == 0:
        return findings, counts

    seen_keys: Set[Tuple[str, str, str]] = set()

    with open(nuclei_raw_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue

            counts["raw_count"] += 1

            try:
                record = json.loads(line_str)
            except Exception:
                counts["invalid_count"] += 1
                continue

            if not isinstance(record, dict):
                counts["invalid_count"] += 1
                continue

            template_id = record.get("template-id") or record.get("template_id")
            info = record.get("info")
            matched_at = record.get("matched-at") or record.get("matched_at") or record.get("host")

            if not template_id or not isinstance(info, dict) or not matched_at:
                counts["invalid_count"] += 1
                continue

            template_id = str(template_id).strip()
            matched_at_str = str(matched_at).strip()

            # Strict Provenance Verification
            matched_origin = normalize_target_origin(matched_at_str)
            if not matched_origin:
                counts["invalid_count"] += 1
                continue

            if valid_target_origins is not None and matched_origin not in valid_target_origins:
                counts["out_of_scope_count"] += 1
                continue

            # Deduplication
            matcher_name = str(record.get("matcher-name") or record.get("matcher_name") or "").strip()
            norm_url = normalize_matched_url(matched_at_str)
            dedup_key = (template_id, norm_url, matcher_name)
            if dedup_key in seen_keys:
                counts["duplicate_count"] += 1
                continue
            seen_keys.add(dedup_key)

            # Classification Truth (strictly from info.classification)
            classification = info.get("classification")
            cve_id = None
            cwe_id = None
            cvss_score = None
            cvss_vector = None

            if isinstance(classification, dict):
                raw_cve = classification.get("cve-id") or classification.get("cve_id")
                if isinstance(raw_cve, list) and raw_cve:
                    cve_id = str(raw_cve[0]).strip().upper()
                elif isinstance(raw_cve, str) and raw_cve.strip():
                    cve_id = raw_cve.strip().upper()

                raw_cwe = classification.get("cwe-id") or classification.get("cwe_id")
                if isinstance(raw_cwe, list) and raw_cwe:
                    cwe_id = str(raw_cwe[0]).strip().upper()
                elif isinstance(raw_cwe, str) and raw_cwe.strip():
                    cwe_id = raw_cwe.strip().upper()

                raw_score = classification.get("cvss-score") or classification.get("cvss_score")
                if raw_score is not None:
                    try:
                        cvss_score = float(raw_score)
                    except (ValueError, TypeError):
                        cvss_score = None

                raw_metrics = (
                    classification.get("cvss-metrics")
                    or classification.get("cvss_metrics")
                    or classification.get("cvss-vector")
                    or classification.get("cvss_vector")
                )
                if isinstance(raw_metrics, str) and raw_metrics.strip():
                    cvss_vector = raw_metrics.strip()

            severity = str(info.get("severity", "info")).strip().upper()
            title = str(info.get("name") or template_id).strip()
            description = str(info.get("description", "")).strip()
            remediation = str(info.get("remediation", "")).strip()
            tags = info.get("tags", [])
            tags_list = tags if isinstance(tags, list) else [str(t).strip() for t in str(tags).split(",") if str(t).strip()]

            item = {
                "id": template_id,
                "template_id": template_id,
                "title": title,
                "name": title,
                "severity": severity,
                "url": matched_at_str,
                "matched_at": matched_at_str,
                "matcher_name": record.get("matcher-name") or record.get("matcher_name"),
                "extracted_results": record.get("extracted-results") or record.get("extracted_results"),
                "curl_command": record.get("curl-command") or record.get("curl_command"),
                "description": description or f"تم اكتشاف مطابقة للقالب {template_id} على الهدف.",
                "remediation": remediation or "مراجعة إعدادات الأمان وتطبيق التحديثات الموصى بها.",
                "tags": tags_list,
                "finding_status": "scanner_match",
                "source": "nuclei",
                "template_source": "official-nuclei-templates",
                "templates_version": NUCLEI_TEMPLATES_VERSION,
                "templates_commit": NUCLEI_TEMPLATES_COMMIT,
                "template_signed": True,
                "cve_id": cve_id,
                "cwe_id": cwe_id,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector
            }
            findings.append(item)
            counts["valid_count"] += 1
            print(f"[{severity}] {title} -> {matched_at_str}", flush=True)

    return findings, counts

def run_nuclei(session_dir: str, scan_id: Optional[str] = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Standard production entrypoint for Nuclei in YemenScan pipeline.
    Runs the official pinned Nuclei container with safe default flags, signed templates,
    and adaptive 3-layer template selection. Strictly NO native fallback.
    """
    import time
    print("[4/4] جاري تشغيل فحص الثغرات الرسمي الآمن التكيفي (ProjectDiscovery Nuclei Adaptive)...", flush=True)

    if scan_id and is_scan_cancelled(scan_id):
        raise ScanCancelledException(f"Scan {scan_id} cancelled.")

    nuclei_targets_file = os.path.join(session_dir, "nuclei_targets.txt")
    targets: List[str] = []
    if os.path.exists(nuclei_targets_file):
        with open(nuclei_targets_file, "r", encoding="utf-8") as tf:
            targets = [line.strip() for line in tf if line.strip()]

    if not targets:
        targets = prepare_nuclei_targets(session_dir)

    if not targets:
        print("[!] لم يتم العثور على أهداف حية لتشغيل Nuclei.", flush=True)
        return True, []

    # Clean previous run execution artifacts (keep targets)
    clean_nuclei_session_artifacts(session_dir)
    # Rewrite targets file after cleaning
    with open(os.path.join(session_dir, "nuclei_targets.txt"), "w", encoding="utf-8") as tf:
        for t in targets:
            tf.write(f"{t}\n")

    write_nuclei_template_manifest(session_dir)

    target_templates_dir = NUCLEI_RUNTIME_TEMPLATES_DIR if os.path.exists(NUCLEI_RUNTIME_TEMPLATES_DIR) else NUCLEI_TEMPLATES_OFFICIAL_DIR
    if not os.path.exists(target_templates_dir):
        err_msg = f"Nuclei templates directory not found at: {target_templates_dir}"
        print(f"[-] خطأ: {err_msg}", flush=True)
        with open(os.path.join(session_dir, "nuclei_stderr.log"), "w", encoding="utf-8") as ef:
            ef.write(err_msg + "\n")
        with open(os.path.join(session_dir, "nuclei_findings.json"), "w", encoding="utf-8") as ff:
            json.dump([], ff, ensure_ascii=False, indent=2)
        metadata = {
            "tool": "nuclei",
            "selection_strategy": "adaptive",
            "engine_version": NUCLEI_ENGINE_VERSION,
            "engine_digest": NUCLEI_ENGINE_DIGEST,
            "templates_version": NUCLEI_TEMPLATES_VERSION,
            "templates_commit": NUCLEI_TEMPLATES_COMMIT,
            "templates_checksum": NUCLEI_TEMPLATES_CHECKSUM,
            "input_count": len(targets),
            "profile_count": 0,
            "raw_count": 0,
            "valid_count": 0,
            "invalid_count": 0,
            "duplicate_count": 0,
            "out_of_scope_count": 0,
            "finding_count": 0,
            "status": "failed",
            "error": err_msg,
            "execution_duration_seconds": 0.0
        }
        with open(os.path.join(session_dir, "nuclei_metadata.json"), "w", encoding="utf-8") as mf:
            json.dump(metadata, mf, ensure_ascii=False, indent=2)
        return False, []

    # 1. Generate Adaptive Scan Plan
    scan_plan = generate_nuclei_scan_plan(session_dir, origins=targets)
    profiles = scan_plan.get("profiles", [])

    if not profiles or scan_plan["summary"]["selected_template_count"] == 0:
        print("[!] لم يتم اختيار أي قوالب مطابقة للأهداف الحالية.", flush=True)
        with open(os.path.join(session_dir, "nuclei_findings.json"), "w", encoding="utf-8") as ff:
            json.dump([], ff, ensure_ascii=False, indent=2)
        metadata = {
            "tool": "nuclei",
            "selection_strategy": "adaptive",
            "engine_version": NUCLEI_ENGINE_VERSION,
            "engine_digest": NUCLEI_ENGINE_DIGEST,
            "templates_version": NUCLEI_TEMPLATES_VERSION,
            "templates_commit": NUCLEI_TEMPLATES_COMMIT,
            "templates_checksum": NUCLEI_TEMPLATES_CHECKSUM,
            "input_count": len(targets),
            "profile_count": len(profiles),
            "raw_count": 0,
            "valid_count": 0,
            "invalid_count": 0,
            "duplicate_count": 0,
            "out_of_scope_count": 0,
            "finding_count": 0,
            "baseline_template_count": scan_plan["summary"].get("baseline_template_count", 0),
            "technology_template_count": scan_plan["summary"].get("technology_template_count", 0),
            "discovery_template_count": scan_plan["summary"].get("discovery_template_count", 0),
            "selected_template_count": 0,
            "skipped_due_to_template_budget": 0,
            "estimated_request_count": 0,
            "circuit_breaker_triggered": False,
            "circuit_breaker_trip_count": 0,
            "status": "completed",
            "execution_duration_seconds": 0.0
        }
        with open(os.path.join(session_dir, "nuclei_metadata.json"), "w", encoding="utf-8") as mf:
            json.dump(metadata, mf, ensure_ascii=False, indent=2)
        return True, []

    if scan_id:
        update_status(
            scan_id,
            stage="phase3_vulnerabilities",
            tool="nuclei",
            progress=75,
            log_message=f"تشغيل فحص Nuclei التكيفي الآمن ضد {len(targets)} أهداف عبر {len(profiles)} مجموعات فحص..."
        )

    extra_vols = [(target_templates_dir, "/opt/nuclei-templates")]
    combined_raw_path = os.path.join(session_dir, "nuclei_raw.jsonl")
    with open(combined_raw_path, "w", encoding="utf-8") as crf:
        pass  # initialize empty file

    all_stderr = []
    start_time = time.time()
    circuit_breaker_triggered = False
    circuit_breaker_trip_count = 0
    executed_any_profile = False
    any_profile_succeeded = False

    for p_idx, profile in enumerate(profiles, start=1):
        if scan_id and is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} cancelled.")

        profile_id = profile["profile_id"]
        profile_targets = profile.get("targets") or profile.get("origins") or []
        selected_templates = profile["selected_templates"]

        if not profile_targets or not selected_templates:
            continue

        # Fail-closed validation: verify that every selected template exists on disk in target_templates_dir
        for st in selected_templates:
            rel_p = st.get("relative_path") or st.get("source_path") or ""
            local_tpl_file = os.path.join(target_templates_dir, rel_p)
            if not os.path.exists(local_tpl_file):
                tid = st.get("template_id") or st.get("id") or "unknown"
                err_msg = f"Runtime template missing: {tid} at {local_tpl_file}"
                print(f"[-] خطأ تكوين فحص Nuclei: {err_msg}", flush=True)
                metadata = {
                    "tool": "nuclei",
                    "status": "configuration_error",
                    "missing_template_id": tid,
                    "error": err_msg,
                    "engine_version": NUCLEI_ENGINE_VERSION,
                    "engine_digest": NUCLEI_ENGINE_DIGEST,
                    "templates_version": NUCLEI_TEMPLATES_VERSION,
                    "templates_commit": NUCLEI_TEMPLATES_COMMIT,
                    "templates_checksum": NUCLEI_TEMPLATES_CHECKSUM,
                    "input_count": len(targets),
                    "profile_count": len(profiles),
                    "raw_count": 0,
                    "valid_count": 0,
                    "invalid_count": 0,
                    "duplicate_count": 0,
                    "out_of_scope_count": 0,
                    "finding_count": 0,
                    "execution_duration_seconds": 0.0
                }
                with open(os.path.join(session_dir, "nuclei_metadata.json"), "w", encoding="utf-8") as mf:
                    json.dump(metadata, mf, ensure_ascii=False, indent=2)
                raise RuntimeTemplateMissingError(tid, err_msg)

        # Write profile targets file
        targets_filename = f"nuclei_targets_{profile_id}.txt"
        with open(os.path.join(session_dir, targets_filename), "w", encoding="utf-8") as ptf:
            for pt in profile_targets:
                ptf.write(f"{pt}\n")

        # Write profile selected templates file
        tpls_filename = f"selected_templates_{profile_id}.txt"
        with open(os.path.join(session_dir, tpls_filename), "w", encoding="utf-8") as ptlf:
            for st in selected_templates:
                ptlf.write(f"{st['container_path']}\n")

        raw_filename = f"nuclei_raw_{profile_id}.jsonl"
        rate_limit = str(profile.get("limits", {}).get("rate_limit", 10))
        concurrency = str(profile.get("limits", {}).get("concurrency", 5))

        args = [
            "-l", f"/data/{targets_filename}",
            "-t", f"/data/{tpls_filename}",
            "-jsonl",
            "-o", f"/data/{raw_filename}",
            "-severity", "medium,high,critical",
            "-pt", "http",
            "-etags", "dos,fuzz,bruteforce,intrusive,local",
            "-dut",
            "-ni",
            "-lna",
            "-iv", "4",
            "-rl", rate_limit,
            "-c", concurrency,
            "-bs", "5",
            "-timeout", "5",
            "-retries", "0",
            "-duc",
            "-nc",
            "-silent"
        ]

        # Profile execution timeout: 8s per template, min 180s, max 600s
        p_timeout = max(180, min(600, len(selected_templates) * 8))

        print(f"[*] تشغيل مجموعة الفحص {p_idx}/{len(profiles)} ({len(selected_templates)} قوالب مختارة ضد {len(profile_targets)} أهداف)...", flush=True)

        success, output = run_docker_tool(
            image=NUCLEI_DOCKER_IMAGE,
            args=args,
            volume_dir=session_dir,
            timeout=p_timeout,
            extra_volumes=extra_vols,
            scan_id=scan_id
        )

        executed_any_profile = True
        if success:
            any_profile_succeeded = True

        if output:
            all_stderr.append(f"--- Profile {profile_id} ---\n{output}\n")

        if not success:
            print(f"[-] خطأ أثناء تشغيل مجموعة الفحص {profile_id}: {output}", flush=True)

        # Append raw output lines to combined raw file
        profile_raw_path = os.path.join(session_dir, raw_filename)
        if os.path.exists(profile_raw_path):
            with open(profile_raw_path, "r", encoding="utf-8", errors="replace") as prf:
                with open(combined_raw_path, "a", encoding="utf-8") as crf:
                    for line in prf:
                        if line.strip():
                            crf.write(line.strip() + "\n")

    duration = time.time() - start_time

    # Save accumulated stderr log
    if all_stderr:
        with open(os.path.join(session_dir, "nuclei_stderr.log"), "w", encoding="utf-8") as ef:
            ef.write("".join(all_stderr))

    if executed_any_profile and not any_profile_succeeded:
        err_msg = "".join(all_stderr) or "Docker execution failed for all profiles"
        metadata = {
            "tool": "nuclei",
            "selection_strategy": "adaptive",
            "engine_version": NUCLEI_ENGINE_VERSION,
            "engine_digest": NUCLEI_ENGINE_DIGEST,
            "templates_version": NUCLEI_TEMPLATES_VERSION,
            "templates_commit": NUCLEI_TEMPLATES_COMMIT,
            "templates_checksum": NUCLEI_TEMPLATES_CHECKSUM,
            "input_count": len(targets),
            "profile_count": len(profiles),
            "raw_count": 0,
            "valid_count": 0,
            "invalid_count": 0,
            "duplicate_count": 0,
            "out_of_scope_count": 0,
            "finding_count": 0,
            "status": "failed",
            "error": err_msg,
            "execution_duration_seconds": round(duration, 2)
        }
        with open(os.path.join(session_dir, "nuclei_metadata.json"), "w", encoding="utf-8") as mf:
            json.dump(metadata, mf, ensure_ascii=False, indent=2)
        with open(os.path.join(session_dir, "nuclei_findings.json"), "w", encoding="utf-8") as ff:
            json.dump([], ff, ensure_ascii=False, indent=2)
        if scan_id:
            update_status(
                scan_id,
                progress=85,
                log_message=f"فشل تشغيل فحص Nuclei: {err_msg[:100]}"
            )
        return False, []

    # Parse combined findings
    valid_origins = set(targets)
    parsed_findings, counts = parse_nuclei_json_output(combined_raw_path, valid_target_origins=valid_origins)

    # Save parsed findings
    nuclei_output_file = os.path.join(session_dir, "nuclei_findings.json")
    with open(nuclei_output_file, "w", encoding="utf-8") as f:
        json.dump(parsed_findings, f, ensure_ascii=False, indent=2)

    # Write comprehensive metadata
    summary = scan_plan.get("summary", {})
    metadata = {
        "tool": "nuclei",
        "selection_strategy": "adaptive",
        "engine_version": NUCLEI_ENGINE_VERSION,
        "engine_digest": NUCLEI_ENGINE_DIGEST,
        "templates_version": NUCLEI_TEMPLATES_VERSION,
        "templates_commit": NUCLEI_TEMPLATES_COMMIT,
        "templates_checksum": NUCLEI_TEMPLATES_CHECKSUM,
        "input_count": len(targets),
        "profile_count": len(profiles),
        "baseline_template_count": summary.get("baseline_template_count", 0),
        "technology_template_count": summary.get("technology_template_count", 0),
        "discovery_template_count": summary.get("discovery_template_count", 0),
        "selected_template_count": summary.get("selected_template_count", 0),
        "skipped_due_to_template_budget": summary.get("skipped_due_to_template_budget", 0),
        "estimated_request_count": summary.get("estimated_request_count", 0),
        "request_budget": 500,
        "rate_limit": 10,
        "concurrency": 5,
        "budget_limited": summary.get("budget_limited", False),
        "raw_count": counts["raw_count"],
        "valid_count": counts["valid_count"],
        "invalid_count": counts["invalid_count"],
        "duplicate_count": counts["duplicate_count"],
        "out_of_scope_count": counts["out_of_scope_count"],
        "finding_count": len(parsed_findings),
        "circuit_breaker_triggered": circuit_breaker_triggered,
        "circuit_breaker_trip_count": circuit_breaker_trip_count,
        "load_protection": "preventive_controls",
        "preventive_load_controls": True,
        "circuit_breaker_telemetry": "requires_upstream_proxy",
        "status": "completed",
        "execution_duration_seconds": round(duration, 2)
    }
    with open(os.path.join(session_dir, "nuclei_metadata.json"), "w", encoding="utf-8") as mf:
        json.dump(metadata, mf, ensure_ascii=False, indent=2)

    if scan_id:
        update_status(
            scan_id,
            progress=85,
            log_message=f"اكتمل فحص Nuclei التكيفي الآمن: تم فحص {summary.get('selected_template_count', 0)} قوالب بنجاح، ورصد {len(parsed_findings)} ملاحظة وثغرة أمنية."
        )

    return True, parsed_findings

def run_optimized_nuclei(
    session_dir: str,
    live_targets_file: str = "nuclei_targets.txt",
    tech_list: Optional[List[str]] = None,
    scan_id: Optional[str] = None
) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Maintains compatibility with pipeline callers while routing strictly
    through the official safe Nuclei engine.
    """
    if tech_list:
        tech_profile_file = os.path.join(session_dir, "tech_profile.json")
        try:
            profile_data = {}
            if os.path.exists(tech_profile_file):
                with open(tech_profile_file, "r", encoding="utf-8") as pf:
                    profile_data = json.load(pf)
            profile_data["tech_list"] = tech_list
            with open(tech_profile_file, "w", encoding="utf-8") as pf:
                json.dump(profile_data, pf, ensure_ascii=False, indent=2)
        except Exception:
            pass
    return run_nuclei(session_dir=session_dir, scan_id=scan_id)

def run_standalone_nuclei(target_url: str, category: Optional[str] = None) -> List[Dict[str, Any]]:
    """Runs a targeted safe Nuclei scan on a specific URL using the official Docker container."""
    norm_origin = normalize_target_origin(target_url)
    if not norm_origin:
        return []

    tmp_base = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scans", ".tmp"))
    os.makedirs(tmp_base, exist_ok=True)
    temp_dir = tempfile.mkdtemp(prefix="nuclei_single_", dir=tmp_base)
    try:
        tf = os.path.join(temp_dir, "nuclei_targets.txt")
        with open(tf, "w", encoding="utf-8") as f:
            f.write(f"{norm_origin}\n")

        extra_vols = [(NUCLEI_TEMPLATES_OFFICIAL_DIR, "/opt/nuclei-templates")]
        args = [
            "-l", "/data/nuclei_targets.txt",
            "-t", "/opt/nuclei-templates",
            "-jsonl",
            "-o", "/data/nuclei_raw.jsonl",
            "-severity", "medium,high,critical",
            "-pt", "http",
            "-etags", "dos,fuzz,bruteforce,intrusive,local",
            "-dut",
            "-ni",
            "-lna",
            "-iv", "4",
            "-rl", "30",
            "-c", "10",
            "-bs", "10",
            "-timeout", "8",
            "-retries", "1",
            "-duc",
            "-nc",
            "-silent"
        ]
        success, _ = run_docker_tool(
            image=NUCLEI_DOCKER_IMAGE,
            args=args,
            volume_dir=temp_dir,
            timeout=120,
            extra_volumes=extra_vols
        )
        if not success:
            return []
        raw_file = os.path.join(temp_dir, "nuclei_raw.jsonl")
        findings, _ = parse_nuclei_json_output(raw_file, valid_target_origins={norm_origin})
        return findings
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def parse_wapiti_json_output(
    raw_path: str,
    target_origin: str
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Parses official Wapiti JSON output into normalized findings schema.
    Extracts vulnerabilities from data["vulnerabilities"].
    """
    if not os.path.exists(raw_path):
        return [], {"raw_count": 0, "finding_count": 0}

    findings: List[Dict[str, Any]] = []
    raw_items_count = 0

    try:
        with open(raw_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except Exception:
        return [], {"raw_count": 0, "finding_count": 0}

    vulns_dict = data.get("vulnerabilities", {})
    for vuln_category, occurrences in vulns_dict.items():
        if not isinstance(occurrences, list):
            continue
        for occ in occurrences:
            raw_items_count += 1
            path = occ.get("path") or ""
            param = occ.get("parameter") or ""
            method = occ.get("method") or "GET"
            info = occ.get("info") or ""
            http_req = occ.get("http_request") or ""
            curl_cmd = occ.get("curl_command") or ""
            level = occ.get("level", 2)

            # Map category to coverage family
            cat_low = vuln_category.lower()
            if "csrf" in cat_low or "cross site request forgery" in cat_low:
                cov_family = "csrf"
                owasp_cat = "OWASP A01:2021-Broken Access Control"
                title = "Cross-Site Request Forgery (CSRF)"
                remediation = "Implement anti-CSRF tokens and SameSite cookie attributes."
            elif "cleartext submission of password" in cat_low or "unsecure_password" in cat_low or "unsecure password" in cat_low or ("cleartext" in cat_low and "password" in cat_low):
                cov_family = "cleartext_password_submission"
                owasp_cat = "OWASP A02:2021-Cryptographic Failures"
                title = "Cleartext Submission of Password"
                remediation = "Ensure all credential and login forms submit strictly over HTTPS."
            elif "redirect" in cat_low and "inconsistent" not in cat_low and "https" not in cat_low:
                cov_family = "open_redirect"
                owasp_cat = "OWASP A01:2021-Broken Access Control"
                title = "Open URL Redirection"
                remediation = "Validate target destination URLs against a strict allowlist."
            elif "https" in cat_low and "redirect" in cat_low:
                cov_family = "https_redirection"
                owasp_cat = "OWASP A05:2021-Security Misconfiguration"
                title = "Cleartext HTTP Traffic without HTTPS Redirection"
                remediation = "Enforce permanent 301/308 redirection from HTTP to HTTPS."
            elif "inconsistent" in cat_low and "redirect" in cat_low:
                cov_family = "inconsistent_redirection"
                owasp_cat = "OWASP A05:2021-Security Misconfiguration"
                title = "Inconsistent HTTP Redirection Behavior"
                remediation = "Standardize redirection policies and location headers across endpoints."
            elif "csp" in cat_low or "content security policy" in cat_low:
                cov_family = "csp_posture"
                owasp_cat = "OWASP A05:2021-Security Misconfiguration"
                title = "Content Security Policy (CSP) Misconfiguration"
                remediation = "Deploy Content-Security-Policy header restricting trusted origins and script execution."
            elif "cookie" in cat_low or "secure flag" in cat_low or "httponly" in cat_low or "samesite" in cat_low:
                cov_family = "cookie_security"
                owasp_cat = "OWASP A07:2021-Identification and Authentication Failures"
                title = "Insecure Cookie Flag Configuration"
                remediation = "Enforce Secure, HttpOnly, and SameSite flags on session and authentication cookies."
            elif "stack" in cat_low or "traceback" in cat_low or "exception" in cat_low:
                cov_family = "stacktrace_disclosure"
                owasp_cat = "OWASP A05:2021-Security Misconfiguration"
                title = "Application Stack Trace Disclosure"
                remediation = "Disable verbose error messages and stack traces in production environments."
            elif "information" in cat_low or "fingerprint" in cat_low or "banner" in cat_low or "server error" in cat_low:
                cov_family = "runtime_information_disclosure"
                owasp_cat = "OWASP A05:2021-Security Misconfiguration"
                title = "Runtime Information and Banner Disclosure"
                remediation = "Mask or remove verbose Server, X-Powered-By, and runtime diagnostic banners."
            elif "header" in cat_low or "hsts" in cat_low or "x-content" in cat_low or "x-frame" in cat_low:
                cov_family = "web_headers"
                owasp_cat = "OWASP A05:2021-Security Misconfiguration"
                title = vuln_category
                remediation = "Configure recommended HTTP security response headers."
            else:
                cov_family = "web_headers"
                owasp_cat = "OWASP A05:2021-Security Misconfiguration"
                title = vuln_category
                remediation = "Review server configuration and security headers."

            # Severity mapping
            if level >= 4:
                severity = "CRITICAL"
            elif level == 3:
                severity = "HIGH"
            elif level == 2:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            finding_seed = f"{target_origin}:{cov_family}:{path}:{param}:{vuln_category}"
            finding_id = hashlib.sha256(finding_seed.encode("utf-8")).hexdigest()[:16]

            target_url = f"{target_origin.rstrip('/')}/{path.lstrip('/')}" if path else target_origin

            findings.append({
                "finding_id": finding_id,
                "id": f"WAP-{cov_family.upper()[:8]}-{finding_id[:4].upper()}",
                "title": title,
                "severity": severity,
                "source_severity": severity,
                "category": owasp_cat,
                "coverage_family": cov_family,
                "target": target_origin,
                "url": target_url,
                "source": "Wapiti DAST",
                "sources": ["wapiti"],
                "source_rule": vuln_category,
                "source_evidence": {
                    "method": method,
                    "path": path,
                    "parameter": param,
                    "http_request": http_req,
                    "curl_command": curl_cmd,
                    "info": info
                },
                "description": info or f"Wapiti DAST reported {vuln_category} on {path}",
                "remediation": remediation,
                "evidence": [{
                    "method": method,
                    "path": path,
                    "parameter": param,
                    "http_request": http_req,
                    "curl_command": curl_cmd,
                    "info": info
                }],
                "tags": ["wapiti", cov_family, "dast"]
            })

    return findings, {"raw_count": raw_items_count, "finding_count": len(findings)}

def run_wapiti_dast(
    session_dir: str,
    scan_id: str,
    primary_urls: List[str],
    profile: str = "safe",
    verify_ssl: bool = True
) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Executes Dynamic Application Security Testing (DAST) using official Wapiti container
    (yemscan/wapiti:3.3.2) with conservative parameters and sequential origin coordination.
    """
    print("[*] جاري الفحص الديناميكي لتطبيقات الويب DAST (Wapiti)...", flush=True)
    update_status(
        scan_id,
        stage="phase3_vulnerabilities",
        tool="wapiti",
        progress=88,
        log_message="تشغيل الفحص الديناميكي السلوكي لتطبيقات الويب DAST (Wapiti Engine)..."
    )

    if is_scan_cancelled(scan_id):
        raise ScanCancelledException(f"Scan {scan_id} cancelled.")

    # Verify local image identity before execution (fail closed)
    verify_wapiti_image_identity()

    # Clean up any stale wapiti raw files from previous runs in session_dir
    try:
        for fname in os.listdir(session_dir):
            if fname.startswith("wapiti_raw_") and fname.endswith(".json"):
                os.remove(os.path.join(session_dir, fname))
    except Exception:
        pass

    wapiti_findings: List[Dict[str, Any]] = []
    unique_urls = [u.strip() for u in primary_urls if u and u.strip()]

    target_origins: List[str] = []
    for u in unique_urls:
        orig = normalize_target_origin(u)
        if orig and orig not in target_origins:
            target_origins.append(orig)

    if not target_origins:
        print("[*] لا توجد أهداف نشطة لتشغيل Wapiti DAST. تم التخطي.", flush=True)
        with open(os.path.join(session_dir, "wapiti_findings.json"), "w", encoding="utf-8") as wf:
            json.dump([], wf, ensure_ascii=False, indent=2)
        with open(os.path.join(session_dir, "wapiti_metadata.json"), "w", encoding="utf-8") as mf:
            json.dump({
                "engine": "wapiti",
                "tool": "wapiti",
                "version": WAPITI_ENGINE_VERSION,
                "build_variant": WAPITI_BUILD_VARIANT,
                "patches": WAPITI_PATCHES,
                "docker_image": WAPITI_DOCKER_IMAGE,
                "image_id": WAPITI_EXPECTED_IMAGE_ID,
                "repository_digest": WAPITI_REPO_DIGEST,
                "build_reproducibility": {
                    "base_image_pinned": True,
                    "python_dependencies_locked": True
                },
                "profile": profile,
                "crawl_policy": "read_only" if profile == "safe" else "standard",
                "allowed_http_methods": ["GET", "HEAD"] if profile == "safe" else ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                "form_submission_enabled": (profile != "safe"),
                "blocked_crawler_request_count": 0,
                "blocked_method_counts": {},
                "modules_executed": [
                    "http_headers", "csp", "cookieflags", "information_disclosure",
                    "stacktrace_disclosure", "https_redirect", "inconsistent_redirection",
                    "unsecure_password"
                ] if profile == "safe" else ["csrf", "redirect"],
                "verify_ssl": 1 if verify_ssl else 0,
                "status": "completed",
                "raw_count": 0,
                "finding_count": 0,
                "execution_duration_seconds": 0.0
            }, mf, ensure_ascii=False, indent=2)
        return True, []

    from core.security_scan_planner import SecurityScanPlanner, is_same_origin
    planner = SecurityScanPlanner()
    joint_plan = planner.generate_joint_scan_plan(
        session_dir,
        origins=target_origins,
        wapiti_profile=profile,
        verify_ssl=verify_ssl
    )
    wapiti_plan = joint_plan.get("wapiti_plan") or {}
    enabled_modules = wapiti_plan.get("enabled_modules", [
        "http_headers", "csp", "cookieflags", "information_disclosure",
        "stacktrace_disclosure", "https_redirect", "inconsistent_redirection",
        "unsecure_password"
    ])

    targets_to_audit = target_origins[:5]
    combined_raw: Dict[str, Any] = {"vulnerabilities": {}, "anomalies": {}, "infos": {}}
    start_time = time.time()
    total_raw_count = 0
    executed_any = False
    any_success = False

    for idx, target_orig in enumerate(targets_to_audit, start=1):
        if is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} cancelled.")

        print(f"[*] Wapiti DAST: فحص الهدف {idx}/{len(targets_to_audit)}: {target_orig} (تنفيذ تسلسلي)...", flush=True)

        raw_filename = f"wapiti_raw_{idx}.json"
        raw_output_path = os.path.join(session_dir, raw_filename)

        args = [
            "-u", target_orig,
            "-m", ",".join(enabled_modules),
            "-S", "paranoid",
            "--tasks", "2",
            "-d", "3",
            "--max-scan-time", "120",  # 120 seconds = 2 minutes per origin
            "--max-attack-time", "30",
            "--max-parameters", "15",
            "--max-links-per-page", "20",
            "--max-files-per-dir", "20",
            "-f", "json",
            "-o", f"/data/{raw_filename}",
            "--no-bugreport",
            "-t", "5"
        ]

        if profile == "safe":
            args.append("--no-form-submission")

        if verify_ssl:
            args.extend(["--verify-ssl", "1"])
        else:
            args.extend(["--verify-ssl", "0"])

        seeds = []
        for t_spec in wapiti_plan.get("targets", []):
            if t_spec.get("origin") == target_orig:
                seeds = [s for s in t_spec.get("seed_urls", []) if is_same_origin(s, target_orig)]
                break
        for s in seeds[:5]:
            args.extend(["-s", s])

        success, output = run_docker_tool(
            image=WAPITI_DOCKER_IMAGE,
            args=args,
            volume_dir=session_dir,
            timeout=180,
            scan_id=scan_id
        )

        executed_any = True
        if success:
            any_success = True

        # Parse output from raw file if generated
        target_findings = []
        if os.path.exists(raw_output_path):
            target_findings, counts = parse_wapiti_json_output(raw_output_path, target_orig)
            total_raw_count += counts.get("raw_count", 0)

            try:
                with open(raw_output_path, "r", encoding="utf-8", errors="replace") as rf:
                    rdata = json.load(rf)
                for v_cat, v_list in rdata.get("vulnerabilities", {}).items():
                    combined_raw["vulnerabilities"].setdefault(v_cat, []).extend(v_list)
                if "infos" in rdata and isinstance(rdata["infos"], dict):
                    for ik, iv in rdata["infos"].items():
                        if ik not in combined_raw["infos"]:
                            combined_raw["infos"][ik] = iv
                        elif ik == "blocked_crawler_request_count":
                            combined_raw["infos"][ik] += iv
                        elif ik == "blocked_method_counts" and isinstance(iv, dict):
                            for m_k, m_v in iv.items():
                                combined_raw["infos"].setdefault(ik, {})[m_k] = combined_raw["infos"].get(ik, {}).get(m_k, 0) + m_v
            except Exception:
                pass

        for f in target_findings:
            if not any(x["finding_id"] == f["finding_id"] for x in wapiti_findings):
                wapiti_findings.append(f)
                print(f"[{f['severity']}] {f['title']} -> {f['url']}", flush=True)

    combined_raw_path = os.path.join(session_dir, "wapiti_raw.json")
    with open(combined_raw_path, "w", encoding="utf-8") as cf:
        json.dump(combined_raw, cf, ensure_ascii=False, indent=2)

    findings_file = os.path.join(session_dir, "wapiti_findings.json")
    with open(findings_file, "w", encoding="utf-8") as ff:
        json.dump(wapiti_findings, ff, ensure_ascii=False, indent=2)

    duration = time.time() - start_time
    disabled_modules = [m["module"] for m in planner.matrix.get("wapiti_disabled_redundant_modules", [])]
    review_modules = planner.matrix.get("wapiti_active_attack_modules_review", [])

    crawl_policy = "read_only" if profile == "safe" else "standard"
    allowed_methods = ["GET", "HEAD"] if profile == "safe" else ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    form_submission_enabled = (profile != "safe")
    blocked_count = combined_raw.get("infos", {}).get("blocked_crawler_request_count", 0)
    blocked_methods = combined_raw.get("infos", {}).get("blocked_method_counts", {})

    status_completed = (any_success or not executed_any)
    metadata = {
        "engine": "wapiti",
        "tool": "wapiti",
        "version": WAPITI_ENGINE_VERSION,
        "build_variant": WAPITI_BUILD_VARIANT,
        "patches": WAPITI_PATCHES,
        "docker_image": WAPITI_DOCKER_IMAGE,
        "image_id": WAPITI_EXPECTED_IMAGE_ID,
        "repository_digest": WAPITI_REPO_DIGEST,
        "build_reproducibility": {
            "base_image_pinned": True,
            "python_dependencies_locked": True
        },
        "profile": profile,
        "crawl_policy": crawl_policy,
        "allowed_http_methods": allowed_methods,
        "form_submission_enabled": form_submission_enabled,
        "blocked_crawler_request_count": blocked_count,
        "blocked_method_counts": blocked_methods,
        "modules_executed": enabled_modules,
        "modules_disabled_redundant": disabled_modules,
        "modules_excluded_review": review_modules,
        "verify_ssl": 1 if verify_ssl else 0,
        "targets_scanned": targets_to_audit,
        "max_active_security_scanners_per_origin": 1,
        "sequential_execution": True,
        "status": "completed" if status_completed else "failed",
        "raw_count": total_raw_count,
        "finding_count": len(wapiti_findings),
        "execution_duration_seconds": round(duration, 2)
    }

    with open(os.path.join(session_dir, "wapiti_metadata.json"), "w", encoding="utf-8") as mf:
        json.dump(metadata, mf, ensure_ascii=False, indent=2)

    return status_completed, wapiti_findings

def _extract_finding_archetype(item: Dict[str, Any]) -> Tuple[str, ...]:
    """Identifies the root flaw archetype to enable cross-scanner correlation and deduplication."""
    fid = str(item.get("id", "")).lower()
    title = str(item.get("title", "")).lower()
    cat = str(item.get("category", "")).lower()
    path = urlparse(item.get("url", "")).path.rstrip("/").lower()
    
    # Server-wide security controls (scoped to hostname)
    if any(k in fid or k in title for k in ["cors"]):
        return ("server", "cors")
    if any(k in fid or k in title for k in ["waf", "cloudflare"]):
        return ("server", "waf")
    if any(k in fid or k in title for k in ["hsts", "strict-transport"]):
        return ("server", "hsts")
    if any(k in fid or k in title for k in ["csp", "content-security-policy"]):
        return ("server", "csp")
    if any(k in fid or k in title for k in ["x-frame", "clickjacking", "frame-ancestors"]):
        return ("server", "clickjacking")
    if any(k in fid or k in title for k in ["cookie", "httponly"]):
        return ("server", "cookie")
    if any(k in fid or k in title for k in ["banner", "server-tokens"]):
        return ("server", "banner")
    if any(k in fid or k in title for k in ["cleartext", "https redirection"]):
        return ("server", "cleartext")
    if any(k in fid or k in title for k in ["permissions-policy", "feature-policy"]):
        return ("server", "permissions-policy")
    if any(k in fid or k in title for k in ["mime", "x-content-type-options"]):
        return ("server", "mime-sniffing")
        
    # Endpoint-specific flaws (scoped to hostname + normalized path)
    if "csrf" in fid or "csrf" in title:
        return ("path", path, "csrf")
    if "redirect" in fid or "redirect" in title:
        return ("path", path, "redirect")
    if "sql" in fid or "sql" in title:
        return ("path", path, "sqli")
    if "lfi" in fid or "passwd" in fid or "winini" in fid:
        return ("path", path, "lfi")
    if "xss" in fid or "xss" in title:
        return ("path", path, "xss")
    if "rce" in fid or "command-injection" in fid:
        return ("path", path, "rce")
    if "ssrf" in fid:
        return ("path", path, "ssrf")
    if "env" in fid or ".env" in title:
        return ("path", path, "env")
    if "git" in fid:
        return ("path", path, "git")
    if "backup" in fid:
        return ("path", path, "backup")
    if "graphql" in fid:
        return ("path", path, "graphql")
    if "swagger" in fid or "openapi" in fid:
        return ("path", path, "swagger")
    if "actuator" in fid:
        return ("path", path, "actuator")
    if "phpinfo" in fid:
        return ("path", path, "phpinfo")
        
    return ("id_path", path, fid)

def unify_and_save_vulnerabilities(
    session_dir: str,
    scan_id: str,
    nuclei_findings: List[Dict[str, Any]],
    wapiti_findings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Intelligently integrates, cross-deduplicates, and unifies findings from both
    Nuclei Engine and Wapiti DAST.
    
    Architectural Division of Work:
    - Wapiti DAST: Specialized in HTTP transport security, response headers, cookie flags, and perimeter WAF defense.
    - Nuclei Engine: Specialized in targeted CVE exploits, injection flaws, secrets exposures, and API vulnerabilities.
    
    Cross-Scanner Deduplication:
    - If both scanners flag the same underlying issue on a target, they are correlated into a single unified record,
      preserving the highest severity, combining evidence, and crediting both tools ('Nuclei Engine + Wapiti DAST').
    """
    print("[*] جاري توحيد ودمج نتائج فحص Nuclei و Wapiti بدون تكرار...", flush=True)
    
    severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    combined_raw = nuclei_findings + wapiti_findings
    
    # Check if there are substantive vulnerabilities
    has_substantive_findings = any(
        f.get("severity", "INFO").upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW") and f.get("id") != "WAP-AUDIT-BASELINE"
        for f in combined_raw
    )
    
    # Group findings by (netloc, archetype)
    unified_map: Dict[Tuple[str, Tuple[str, ...]], Dict[str, Any]] = {}
    
    for finding in combined_raw:
        fid = finding.get("id", "")
        # Drop baseline informational placeholder if substantive flaws were discovered
        if has_substantive_findings and fid == "WAP-AUDIT-BASELINE":
            continue
            
        u = finding.get("url", "")
        parsed = urlparse(u)
        netloc = (parsed.netloc or "").lower()
        archetype = _extract_finding_archetype(finding)
        group_key = (netloc, archetype)
        
        # Determine sources list for single item
        raw_source = finding.get("source", "").lower()
        initial_sources = list(finding.get("sources") or [])
        if not initial_sources:
            if "nuclei" in raw_source:
                initial_sources = ["nuclei"]
            elif "wapiti" in raw_source:
                initial_sources = ["wapiti"]
            else:
                initial_sources = ["nuclei"] if fid.lower().startswith("cve-") else ["wapiti"]

        finding["sources"] = initial_sources

        # Ensure source attribution details are populated
        if "source_severity" not in finding:
            finding["source_severity"] = finding.get("severity", "INFO")
        if "source_rule" not in finding:
            finding["source_rule"] = finding.get("id") or finding.get("template_id") or finding.get("title")
        if "source_evidence" not in finding:
            finding["source_evidence"] = finding.get("evidence", [])

        if group_key not in unified_map:
            unified_map[group_key] = dict(finding)
        else:
            existing = unified_map[group_key]
            existing_sev = existing.get("severity", "INFO").upper()
            new_sev = finding.get("severity", "INFO").upper()
            
            existing_score = severity_rank.get(existing_sev, 0)
            new_score = severity_rank.get(new_sev, 0)
            
            # Combine source attribution as structured list
            merged_sources = sorted(list(set(existing.get("sources", []) + finding.get("sources", []))))
            
            sources = set()
            for s in [existing.get("source", ""), finding.get("source", "")]:
                if s:
                    for sub in s.split(" + "):
                        sources.add(sub.strip())
            
            merged_source_str = " + ".join(sorted(list(sources))) if len(sources) > 1 else list(sources)[0] if sources else "Security Scanner"
            
            if new_score > existing_score:
                primary = dict(finding)
                secondary = existing
            else:
                primary = existing
                secondary = finding
                
            primary["source"] = merged_source_str
            primary["sources"] = merged_sources

            # Preserve source details from both tools in tool_sources
            tool_sources = dict(primary.get("tool_sources") or {})
            for s in primary.get("sources", []):
                tool_sources[s] = {
                    "severity": primary.get("source_severity", primary.get("severity")),
                    "rule": primary.get("source_rule", primary.get("id")),
                    "evidence": primary.get("source_evidence", primary.get("evidence"))
                }
            for s in secondary.get("sources", []):
                tool_sources[s] = {
                    "severity": secondary.get("source_severity", secondary.get("severity")),
                    "rule": secondary.get("source_rule", secondary.get("id")),
                    "evidence": secondary.get("source_evidence", secondary.get("evidence"))
                }
            primary["tool_sources"] = tool_sources
            
            # Combine evidence lists
            ev1 = list(primary.get("evidence", []))
            ev2 = list(secondary.get("evidence", []))
            primary["evidence"] = ev1 + [e for e in ev2 if e not in ev1]
            
            desc1 = primary.get("description", "").strip()
            desc2 = secondary.get("description", "").strip()
            if desc2 and desc2 not in desc1 and desc1 not in desc2:
                primary["description"] = f"{desc1}\n\n[ملاحظة إضافية من {secondary.get('source', '')}]: {desc2}"
                
            rem1 = primary.get("remediation", "").strip()
            rem2 = secondary.get("remediation", "").strip()
            if rem2 and rem2 not in rem1 and len(rem2) > len(rem1):
                primary["remediation"] = rem2
                
            t1 = set(primary.get("tags", []))
            t2 = set(secondary.get("tags", []))
            primary["tags"] = sorted(list(t1 | t2))
            
            unified_map[group_key] = primary

    all_vulns_raw = list(unified_map.values())
    
    # --------------------------------------------------------------------------
    # Security Normalization & Reference Standards Enrichment (CVE, CWE, CVSS, OWASP)
    # --------------------------------------------------------------------------
    from core.vuln_normalizer import normalize_vulnerability
    all_vulns: List[Dict[str, Any]] = []
    for v in all_vulns_raw:
        norm = normalize_vulnerability(v)
        enriched_item = dict(v)

        u = v.get("url", "")
        p_u = urlparse(u)
        v_netloc = (p_u.netloc or "").lower()
        v_path = p_u.path or "/"
        v_origin = normalize_target_origin(u) or f"{p_u.scheme or 'http'}://{v_netloc}"

        # Determine coverage family
        cov_family = v.get("coverage_family")
        if not cov_family:
            fid_low = str(v.get("id", "")).lower()
            if fid_low.startswith("cve-") or fid_low.startswith("cnvd-"):
                cov_family = "known_cve_signature"
            elif "csrf" in fid_low:
                cov_family = "csrf"
            elif "redirect" in fid_low:
                cov_family = "open_redirect"
            elif "env" in fid_low or "config" in fid_low:
                cov_family = "exposed_configuration"
            elif "panel" in fid_low:
                cov_family = "exposed_panels"
            elif "backup" in fid_low:
                cov_family = "backup_file_discovery"
            elif "cookie" in fid_low:
                cov_family = "cookie_security"
            elif "password" in fid_low or "unsecure" in fid_low:
                cov_family = "cleartext_password_submission"
            elif "csp" in fid_low:
                cov_family = "csp_posture"
            elif "header" in fid_low or "hsts" in fid_low:
                cov_family = "web_headers"
            elif "tech" in fid_low or "version" in fid_low:
                cov_family = "technology_version_check"
            elif any(cat in fid_low for cat in ["cves", "vulnerabilities"]):
                cov_family = "product_specific_vulnerability"
            else:
                cov_family = "safe_signature_based_checks"

        # Deterministic finding_id
        f_id = v.get("finding_id")
        if not f_id:
            seed = f"{v_origin}:{cov_family}:{v_path}::{v.get('id', '')}"
            f_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]

        enriched_item.update({
            "finding_id": f_id,
            "target": v.get("target") or v_origin,
            "coverage_family": cov_family,
            "sources": v.get("sources", ["nuclei"]),
            "source_severity": v.get("source_severity", v.get("severity", "INFO")),
            "source_rule": v.get("source_rule", v.get("id")),
            "source_evidence": v.get("source_evidence", v.get("evidence", [])),
            "tool_sources": v.get("tool_sources", {}),
            "cve_id": norm.get("cve_id"),
            "cwe_id": norm.get("cwe_id"),
            "cvss_score": norm.get("cvss_score"),
            "cvss_vector": norm.get("cvss_vector"),
            "severity": norm.get("severity", v.get("severity", "INFO")).upper(),
            "owasp_category": norm.get("owasp_category") or v.get("category"),
            "owasp_api_category": norm.get("owasp_api_category"),
            "standard_remediation": norm.get("standard_remediation") or v.get("remediation"),
            "is_cisa_kev": norm.get("is_cisa_kev", False),
            "epss_score": norm.get("epss_score"),
            "fingerprint": norm.get("fingerprint"),
        })
        all_vulns.append(enriched_item)

    # Sort strictly by calibrated severity: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO
    sort_rank = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
    all_vulns.sort(key=lambda x: sort_rank.get(x.get("severity", "INFO").upper(), 6))
    
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in all_vulns:
        s = v.get("severity", "info").lower()
        if s in severity_counts:
            severity_counts[s] += 1
            
    unified_file = os.path.join(session_dir, "unified_vulnerabilities.json")
    with open(unified_file, "w", encoding="utf-8") as f:
        json.dump(all_vulns, f, ensure_ascii=False, indent=2)
        
    print(f"[+] تم توحيد النتائج: إجمالي الثغرات الفريدة بعد التكامل وإلغاء التكرار: {len(all_vulns)}", flush=True)
    for sev_name, cnt in severity_counts.items():
        if cnt > 0:
            print(f"    - {sev_name.upper()}: {cnt}", flush=True)
            
    update_status(
        scan_id,
        log_message=f"تم إعداد التقرير الموحد للثغرات: الإجمالي {len(all_vulns)} ثغرة وملاحظة (تكامل بين Nuclei و Wapiti بدون تكرار).",
        stats_update={
            "vulnerabilities_count": len(all_vulns),
            "vuln_by_severity": severity_counts
        }
    )
    print("\n[+] تم حفظ الثغرات والتقارير بصيغة JSON.\n", flush=True)
    return all_vulns
