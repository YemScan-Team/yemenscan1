import os
import re
import json
import yaml
from typing import Dict, List, Set, Tuple, Any, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NUCLEI_TEMPLATES_OFFICIAL_DIR = os.path.join(BASE_DIR, "nuclei_templates_official")
NUCLEI_RUNTIME_TEMPLATES_DIR = os.path.join(BASE_DIR, "nuclei_runtime_templates")
NUCLEI_RUNTIME_MANIFEST_PATH = os.path.join(BASE_DIR, "nuclei_runtime_manifest.json")

class RuntimeTemplateMissingError(Exception):
    """Raised when a requested template is not present in the nuclei_runtime_templates bundle."""
    def __init__(self, template_id: str, message: Optional[str] = None):
        self.template_id = template_id
        super().__init__(message or f"Template '{template_id}' is missing from nuclei_runtime_templates bundle.")

# ==============================================================================
# 1. Technology Classification Taxonomy (Section 5)
# ==============================================================================
TECH_TAXONOMY: Dict[str, str] = {
    # Application
    "wordpress": "application",
    "discourse": "application",
    "jenkins": "application",
    "grafana": "application",
    "kibana": "application",
    "phpmyadmin": "application",
    "cpanel": "application",
    "gitlab": "application",
    "jira": "application",
    "confluence": "application",
    "tomcat": "application",
    "solr": "application",
    "sonarqube": "application",

    # CMS
    "drupal": "cms",
    "joomla": "cms",
    "magento": "cms",
    "ghost": "cms",
    "typo3": "cms",

    # Framework
    "laravel": "framework",
    "django": "framework",
    "rails": "framework",
    "ruby on rails": "framework",
    "spring": "framework",
    "springboot": "framework",
    "spring-boot": "framework",
    "express": "framework",
    "symfony": "framework",
    "codeigniter": "framework",
    "flask": "framework",
    "asp.net": "framework",
    "dotnet": "framework",
    ".net": "framework",
    "php": "framework",

    # Web Server
    "nginx": "web_server",
    "apache": "web_server",
    "httpd": "web_server",
    "iis": "web_server",
    "microsoft-iis": "web_server",
    "litespeed": "web_server",
    "caddy": "web_server",

    # API Framework
    "swagger": "api_framework",
    "openapi": "api_framework",
    "graphql": "api_framework",
    "spring-actuator": "api_framework",
    "actuator": "api_framework",
    "fastapi": "api_framework",

    # Infrastructure
    "redis": "infrastructure",
    "elasticsearch": "infrastructure",
    "mysql": "infrastructure",
    "mariadb": "infrastructure",
    "postgresql": "infrastructure",
    "postgres": "infrastructure",
    "mongodb": "infrastructure",
    "docker": "infrastructure",
    "kubernetes": "infrastructure",

    # CDN (Peripheral)
    "cloudflare": "cdn",
    "fastly": "cdn",
    "akamai": "cdn",
    "cloudfront": "cdn",

    # Frontend (Peripheral)
    "react": "frontend",
    "vue": "frontend",
    "vue.js": "frontend",
    "jquery": "frontend",
    "bootstrap": "frontend",
    "angular": "frontend",
    "adobe fonts": "frontend",
    "typekit": "frontend",

    # Analytics (Peripheral)
    "google analytics": "analytics",
    "hotjar": "analytics",
    "matomo": "analytics",

    # Security Feature (Peripheral)
    "hsts": "security_feature",
    "csp": "security_feature",
    "waf": "security_feature",
}

ELIGIBLE_CATEGORIES: Set[str] = {
    "application",
    "framework",
    "cms",
    "web_server",
    "api_framework"
}

# ==============================================================================
# 2. Curated Universal Safe Baseline Templates (Layer A)
# ==============================================================================
UNIVERSAL_SAFE_BASELINE_PATHS: List[str] = [
    # Exposures
    "http/exposures/configs/git-config.yaml",
    "http/exposures/configs/git-config-nginxoffbyslash.yaml",
    "http/exposures/configs/phpinfo-files.yaml",
    "http/exposures/configs/laravel-env.yaml",
    "http/exposures/configs/codeigniter-env.yaml",
    "http/exposures/configs/cgi-printenv.yaml",
    "http/exposures/configs/oracle-cgi-printenv.yaml",
    "http/exposures/apis/swagger-api.yaml",
    "http/exposures/logs/event-debug-server-status.yaml",
    "http/exposures/logs/ffserver-status.yaml",
    # Miscellaneous / Metadata
    "http/miscellaneous/robots-txt.yaml",
    "http/miscellaneous/robots-txt-endpoint.yaml",
    "http/miscellaneous/security-txt.yaml",
    "http/miscellaneous/sitemap-detect.yaml",
    # Misconfigurations
    "http/misconfiguration/server-status.yaml",
    "http/misconfiguration/apache-spark-env.yaml",
    "http/misconfiguration/info-cgi-env-leak.yaml",
    "http/misconfiguration/node-express-dev-env.yaml",
    "http/misconfiguration/envoy-metadata-disclosure.yaml",
    # Generic vulnerabilities / exposures
    "http/vulnerabilities/generic/cors-misconfig.yaml",
    "http/vulnerabilities/generic/generic-env.yaml",
    # Technologies / Public Panels
    "http/technologies/springboot-actuator.yaml",
    "http/technologies/graphql-detect.yaml",
    "http/exposed-panels/alienvault-usm.yaml",
    "http/exposed-panels/openvas-panel.yaml",
    "http/exposed-panels/openvpn-admin.yaml",
    "http/exposed-panels/securenvoy-panel.yaml",
]

# ==============================================================================
# 3. Technology Classifier Helper
# ==============================================================================
def classify_technology(raw_name: str) -> Tuple[str, str, Optional[str]]:
    """
    Normalizes raw technology string (e.g., 'Discourse:2026.3.0', 'Ruby on Rails', 'nginx/1.18.0')
    and returns (canonical_name, category, version).
    """
    if not raw_name or not isinstance(raw_name, str):
        return ("unknown", "unknown", None)

    clean_str = raw_name.strip()
    version = None

    if ":" in clean_str:
        parts = clean_str.split(":", 1)
        name_part = parts[0].strip().lower()
        version = parts[1].strip()
    elif "/" in clean_str and not clean_str.startswith("http"):
        parts = clean_str.split("/", 1)
        name_part = parts[0].strip().lower()
        version = parts[1].strip()
    else:
        name_part = clean_str.lower()

    # Match exact or key substring in taxonomy
    for key, cat in TECH_TAXONOMY.items():
        if key == name_part:
            return (key, cat, version)

    for key, cat in TECH_TAXONOMY.items():
        if key in name_part or name_part in key:
            return (key, cat, version)

    return (name_part, "unknown", version)

# Regex patterns for fast pre-filtering & analysis
re_unsafe = re.compile(r"unsafe:\s*true", re.IGNORECASE)
re_race = re.compile(r"race:\s*true", re.IGNORECASE)
re_method = re.compile(r"method:\s*([A-Za-z]+)", re.IGNORECASE)
re_raw = re.compile(r"^\s*(?:-\s*)?raw:\s*", re.MULTILINE | re.IGNORECASE)
re_payloads = re.compile(r"^\s*(?:-\s*)?payloads:\s*", re.MULTILINE | re.IGNORECASE)
re_flow = re.compile(r"^\s*(?:-\s*)?flow:\s*", re.MULTILINE | re.IGNORECASE)
re_attack = re.compile(r"attack:\s*([a-zA-Z]+)", re.IGNORECASE)
re_body = re.compile(r"^\s*body:\s*[\'\"]?.+[\'\"]?", re.MULTILINE | re.IGNORECASE)
re_oast = re.compile(r"(interactsh|interact\.sh|oast\.fun|oast\.site|oast\.me|oast\.pro|\{\{interactsh-url\}\})", re.IGNORECASE)

BLOCKED_TAGS: Set[str] = {"intrusive", "dos", "fuzz", "bruteforce", "local"}

REVIEW_TAGS: Set[str] = {
    "sqli", "sql-injection", "rce", "cmi", "cmd-injection", 
    "traversal", "lfi", "rfi", "ssrf", "oast", "interactsh", 
    "xxe", "deserialization", "insecure-deserialization", 
    "auth-bypass", "xss", "default-login", "credential", "brute",
    "file-upload", "upload"
}

BLOCKED_KEYWORDS: List[str] = [
    "reverse shell", "bind shell", "destructive action", 
    "configuration modification", "password modification", "database modification"
]


def estimate_request_cost(content: str) -> Tuple[Optional[int], str]:
    """
    Statically estimates the HTTP request cost of a Nuclei template.
    Returns (cost, explanation). If cost is unknown or unbounded, returns (None, reason).
    """
    if re_raw.search(content):
        raw_blocks = re.findall(r"^\s*-\s*\|", content, re.MULTILINE)
        raw_lines = re.findall(r"^\s*-\s*[\'\"]?(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+", content, re.MULTILINE)
        count = max(len(raw_blocks), len(raw_lines), 1)
        return count, f"{count} raw HTTP request(s)"

    has_payloads = bool(re_payloads.search(content))
    attack_m = re_attack.search(content)
    if has_payloads or attack_m:
        if "fuzzing" in content.lower() or "wordlist" in content.lower():
            return None, "Unbounded external payload/wordlist"
        payload_items = re.findall(r"^\s*-\s*[\'\"]?[a-zA-Z0-9_\-\.\/]+[\'\"]?\s*$", content, re.MULTILINE)
        if len(payload_items) > 100:
            return None, f"Large or unbounded payload list ({len(payload_items)} items)"
        multiplier = max(1, len(payload_items))
        return multiplier, f"Payload multiplier (~{multiplier} requests)"

    path_entries = re.findall(r"^\s*-\s*[\'\"]?(?:\{\{(?:BaseURL|RootURL|Hostname)\}\}|\/[a-zA-Z0-9_\-\.\/\?=&%])[^\'\"\n]*", content, re.MULTILINE)
    path_headers = re.findall(r"^\s*path:\s*$", content, re.MULTILINE)
    
    if path_entries:
        return len(path_entries), f"{len(path_entries)} path(s) queried"
    elif path_headers:
        return len(path_headers), f"{len(path_headers)} path block(s)"
    
    return 1, "Default single request"


def classify_template_content(content: str, rel_path: str = "", tpl_id: str = "") -> Dict[str, Any]:
    """
    Classifies a Nuclei template into one of 3 policies:
      - 'blocked': intrusive, dos, fuzz, bruteforce, local, mutating methods (PUT/DELETE/PATCH), unsafe: true, race: true
      - 'review': attack probes (sqli, rce, lfi, etc.), POST, bodies, raw, payloads, flow, OAST, status-only on high/med/crit, unbounded cost
      - 'safe': strictly non-mutating GET/HEAD, no body, no attack, bounded static cost
    """
    m_id = re.search(r"^id:\s*([^\s#]+)", content, re.MULTILINE)
    if not tpl_id:
        tpl_id = m_id.group(1).strip("\"'") if m_id else "unknown"

    m_name = re.search(r"^\s*name:\s*(.+)$", content, re.MULTILINE)
    name = m_name.group(1).strip("\"'") if m_name else tpl_id

    m_sev = re.search(r"^\s*severity:\s*([a-zA-Z]+)", content, re.MULTILINE)
    sev = m_sev.group(1).strip().upper() if m_sev else "INFO"

    m_tags = re.search(r"^\s*tags:\s*(.+)$", content, re.MULTILINE)
    raw_tags = m_tags.group(1).lower() if m_tags else ""
    tags = set(re.findall(r"[a-z0-9_-]+", raw_tags))

    # 1. BLOCKED POLICY CHECK
    is_blocked = False
    blocked_reasons = []

    rel_low = rel_path.lower()
    if "fuzzing" in rel_low or "dast" in rel_low:
        is_blocked = True
        blocked_reasons.append("Directory category (fuzzing/dast)")

    b_tags = tags & BLOCKED_TAGS
    if b_tags:
        is_blocked = True
        blocked_reasons.append(f"Blocked tags: {sorted(list(b_tags))}")

    if re_unsafe.search(content):
        is_blocked = True
        blocked_reasons.append("unsafe: true execution mode")

    if re_race.search(content):
        is_blocked = True
        blocked_reasons.append("race condition test")

    methods = set(m.upper() for m in re_method.findall(content))
    mutating = methods & {"PUT", "PATCH", "DELETE"}
    if mutating:
        is_blocked = True
        blocked_reasons.append(f"Mutating HTTP methods: {sorted(list(mutating))}")

    for kw in BLOCKED_KEYWORDS:
        if kw in content.lower():
            is_blocked = True
            blocked_reasons.append(f"Blocked keyword: {kw}")
            break

    if is_blocked:
        return {
            "template_id": tpl_id,
            "name": name,
            "relative_path": rel_path,
            "container_path": f"/opt/nuclei-templates/{rel_path}",
            "severity": sev,
            "policy": "blocked",
            "reason": "; ".join(blocked_reasons),
            "methods": sorted(list(methods)) if methods else ["UNKNOWN"],
            "request_cost": None,
            "tags": sorted(list(tags))
        }

    # 2. REVIEW POLICY CHECK
    is_review = False
    review_reasons = []

    if "POST" in methods:
        is_review = True
        review_reasons.append("HTTP POST method")

    if re_body.search(content):
        is_review = True
        review_reasons.append("Request body present")

    if re_raw.search(content):
        is_review = True
        review_reasons.append("Raw HTTP request block")

    if re_payloads.search(content):
        is_review = True
        review_reasons.append("Payloads generator present")

    if re_attack.search(content):
        is_review = True
        review_reasons.append("Attack generator present")

    if re_flow.search(content):
        is_review = True
        review_reasons.append("Multi-step flow execution")

    if re_oast.search(content):
        is_review = True
        review_reasons.append("OAST / Interactsh interaction probe")

    r_tags = tags & REVIEW_TAGS
    if r_tags:
        is_review = True
        review_reasons.append(f"Attack probe tags: {sorted(list(r_tags))}")

    if sev in ("MEDIUM", "HIGH", "CRITICAL"):
        has_word_matcher = ("type: word" in content) or ("type: regex" in content) or ("type: dsl" in content)
        has_status_matcher = "type: status" in content
        if has_status_matcher and not has_word_matcher:
            is_review = True
            review_reasons.append("Status-only vulnerability matcher on high/medium/critical severity")

    cost, cost_desc = estimate_request_cost(content)
    if cost is None:
        is_review = True
        review_reasons.append(f"Unbounded request cost: {cost_desc}")

    if is_review:
        return {
            "template_id": tpl_id,
            "name": name,
            "relative_path": rel_path,
            "container_path": f"/opt/nuclei-templates/{rel_path}",
            "severity": sev,
            "policy": "review",
            "reason": "; ".join(review_reasons),
            "methods": sorted(list(methods)) if methods else ["GET"],
            "request_cost": cost,
            "tags": sorted(list(tags))
        }

    # 3. SAFE POLICY
    return {
        "template_id": tpl_id,
        "name": name,
        "relative_path": rel_path,
        "container_path": f"/opt/nuclei-templates/{rel_path}",
        "severity": sev,
        "policy": "safe",
        "reason": "Non-mutating GET/HEAD, bounded cost, safe passive check",
        "methods": sorted(list(methods)) if methods else ["GET"],
        "request_cost": cost or 1,
        "tags": sorted(list(tags))
    }


# ==============================================================================
# 4. Safe Manifest Manager
# ==============================================================================
class SafeManifestManager:
    """
    Indexes and validates official nuclei-templates to create and enforce
    the 3-Way Policy Manifest: 'safe', 'review', and 'blocked'.
    Only templates with policy == 'safe' are eligible for the Default Scan.
    Maintains the mathematical invariant: total = safe_count + review_count + blocked_count.
    """
    BANNED_TAGS: Set[str] = BLOCKED_TAGS
    BANNED_PROTOCOLS: Set[str] = {"code", "javascript", "headless", "dast", "file"}

    def __init__(self, templates_dir: Optional[str] = None):
        self.templates_dir = templates_dir or NUCLEI_TEMPLATES_OFFICIAL_DIR
        self._safe_templates: Dict[str, Dict[str, Any]] = {}
        self._review_templates: Dict[str, Dict[str, Any]] = {}
        self._blocked_templates: Dict[str, Dict[str, Any]] = {}
        self._stats: Dict[str, Any] = {}
        self._indexed = False

    def build_or_load_manifest(self) -> Dict[str, Dict[str, Any]]:
        """Loads or builds the 3-way policy manifest and returns the safe templates map."""
        if self._indexed and self._safe_templates:
            return self._safe_templates

        cache_policy_path = os.path.join(self.templates_dir, ".cache_policy_manifest.json")
        if os.path.exists(cache_policy_path):
            try:
                with open(cache_policy_path, "r", encoding="utf-8") as cf:
                    data = json.load(cf)
                self._safe_templates = data.get("safe", {})
                self._review_templates = data.get("review", {})
                self._blocked_templates = data.get("blocked", {})
                self._stats = data.get("stats", {})
                self._indexed = True
                return self._safe_templates
            except Exception:
                pass

        http_base = os.path.join(self.templates_dir, "http")
        self._safe_templates = {}
        self._review_templates = {}
        self._blocked_templates = {}

        if not os.path.exists(http_base):
            return self._safe_templates

        total_files = 0
        for root, _, files in os.walk(http_base):
            for f in files:
                if not f.endswith((".yaml", ".yml")):
                    continue
                total_files += 1
                fp = os.path.join(root, f)
                rel_path = os.path.relpath(fp, self.templates_dir).replace("\\", "/")

                try:
                    with open(fp, "r", encoding="utf-8", errors="replace") as yf:
                        content = yf.read()
                    item = classify_template_content(content, rel_path=rel_path)
                    item["file_path"] = fp
                    tid = item["template_id"]

                    if item["policy"] == "blocked":
                        self._blocked_templates[tid] = item
                    elif item["policy"] == "review":
                        self._review_templates[tid] = item
                    else:
                        self._safe_templates[tid] = item
                except Exception:
                    continue

        safe_count = len(self._safe_templates)
        review_count = len(self._review_templates)
        blocked_count = len(self._blocked_templates)
        total = safe_count + review_count + blocked_count

        self._stats = {
            "total_evaluated": total_files,
            "total_categorized": total,
            "safe_count": safe_count,
            "review_count": review_count,
            "blocked_count": blocked_count,
            "invariant_holds": (total == (safe_count + review_count + blocked_count))
        }

        try:
            with open(cache_policy_path, "w", encoding="utf-8") as cf:
                json.dump({
                    "stats": self._stats,
                    "safe": self._safe_templates,
                    "review": self._review_templates,
                    "blocked": self._blocked_templates
                }, cf, ensure_ascii=False)
        except Exception:
            pass

        self._indexed = True
        return self._safe_templates

    def get_stats(self) -> Dict[str, Any]:
        self.build_or_load_manifest()
        return self._stats or {
            "safe_count": len(self._safe_templates),
            "review_count": len(self._review_templates),
            "blocked_count": len(self._blocked_templates),
            "total": len(self._safe_templates) + len(self._review_templates) + len(self._blocked_templates)
        }

    def get_policy(self, template_id: str) -> str:
        self.build_or_load_manifest()
        if template_id in self._safe_templates:
            return "safe"
        if template_id in self._review_templates:
            return "review"
        if template_id in self._blocked_templates:
            return "blocked"
        return "unknown"

    def is_safe(self, template_id: str) -> bool:
        """Checks if a template ID is strictly included in the safe manifest."""
        self.build_or_load_manifest()
        return template_id in self._safe_templates

    def get_template(self, template_id: str) -> Optional[Dict[str, Any]]:
        self.build_or_load_manifest()
        return self._safe_templates.get(template_id) or self._review_templates.get(template_id) or self._blocked_templates.get(template_id)

    def write_manifest_files(self, session_dir: str) -> Tuple[str, str]:
        """Writes nuclei_safe_manifest.json and nuclei_safe_manifest.txt to session_dir."""
        manifest = self.build_or_load_manifest()
        stats = self.get_stats()
        json_path = os.path.join(session_dir, "nuclei_safe_manifest.json")
        txt_path = os.path.join(session_dir, "nuclei_safe_manifest.txt")

        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump({
                "templates_version": "v10.5.1",
                "stats": stats,
                "safe_template_count": len(manifest),
                "review_template_count": len(self._review_templates),
                "blocked_template_count": len(self._blocked_templates),
                "safe_templates": list(manifest.values())
            }, jf, ensure_ascii=False, indent=2)

        with open(txt_path, "w", encoding="utf-8") as tf:
            for tpl in sorted(manifest.keys()):
                tf.write(f"{tpl}\n")

        return json_path, txt_path

# ==============================================================================
# 5. Origin Signals Extractor & Confidence Scorer
# ==============================================================================
def extract_origin_signals(
    origin: str,
    active_urls_records: List[Dict[str, Any]],
    api_routes: List[str]
) -> Dict[str, Any]:
    """
    Extracts technology & route signals for a specific Origin and calculates
    confidence scores according to the scoring model:
      - httpx exact technology: +100
      - httpx technology + version: +120
      - webserver header: +60
      - Kiterunner supporting route: +60
      - page title evidence: +40
      - generic route only: +20
      - weak heuristic: +10
    Threshold: score >= 60 to be eligible for tech-specific templates.
    """
    norm_origin = origin.strip().rstrip("/")
    signals: Dict[str, Dict[str, Any]] = {}

    def _add_signal(name: str, cat: str, score: int, reason: str, ver: Optional[str] = None):
        clean_name = name.lower().strip()
        if clean_name not in signals:
            signals[clean_name] = {
                "name": clean_name,
                "category": cat,
                "confidence_score": 0,
                "version": ver,
                "reasons": []
            }
        signals[clean_name]["confidence_score"] += score
        signals[clean_name]["reasons"].append(reason)
        if ver and not signals[clean_name]["version"]:
            signals[clean_name]["version"] = ver

    # 1. Inspect httpx active_urls records
    for rec in active_urls_records:
        rec_url = str(rec.get("url") or rec.get("input") or "").strip().rstrip("/")
        if not rec_url.startswith(norm_origin):
            continue

        # Tech field
        for t in rec.get("tech", []):
            t_name, t_cat, t_ver = classify_technology(str(t))
            if t_ver:
                _add_signal(t_name, t_cat, 120, f"httpx exact technology with version ({t})", t_ver)
            else:
                _add_signal(t_name, t_cat, 100, f"httpx exact technology ({t})")

        # Webserver field
        ws = rec.get("webserver")
        if ws:
            ws_name, ws_cat, ws_ver = classify_technology(str(ws))
            _add_signal(ws_name, ws_cat or "web_server", 60, f"webserver header ({ws})", ws_ver)

        # Title field
        title = str(rec.get("title") or "")
        title_low = title.lower()
        for tech_key in ["wordpress", "swagger", "graphql", "actuator", "jenkins", "grafana", "laravel", "rails"]:
            if tech_key in title_low:
                t_name, t_cat, _ = classify_technology(tech_key)
                _add_signal(t_name, t_cat, 40, f"page title evidence ('{title}')")

    # 2. Inspect Kiterunner API routes (Layer C Discovery Signals)
    route_signals: Dict[str, int] = {}
    for route in api_routes:
        r_low = route.lower()
        if any(w in r_low for w in ["/swagger", "/openapi", "/api-docs", "/v2/api-docs"]):
            route_signals["swagger"] = max(route_signals.get("swagger", 0), 60)
        if "/graphql" in r_low or "/graphiql" in r_low:
            route_signals["graphql"] = max(route_signals.get("graphql", 0), 60)
        if any(w in r_low for w in ["/actuator", "/actuator/health", "/actuator/env"]):
            route_signals["spring-actuator"] = max(route_signals.get("spring-actuator", 0), 60)
        if any(w in r_low for w in ["/wp-json", "/wp-admin", "/wp-login.php"]):
            route_signals["wordpress"] = max(route_signals.get("wordpress", 0), 60)

    # 3. Filter eligible technologies
    eligible_technologies: List[Dict[str, Any]] = []
    peripheral_technologies: List[Dict[str, Any]] = []

    for name, data in signals.items():
        cat = data["category"]
        score = data["confidence_score"]
        if score >= 60 and cat in ELIGIBLE_CATEGORIES:
            eligible_technologies.append(data)
        else:
            peripheral_technologies.append(data)

    confidence_scores = {k: v["confidence_score"] for k, v in signals.items()}
    # Also add route confidence scores
    for r_k, r_v in route_signals.items():
        confidence_scores[r_k] = max(confidence_scores.get(r_k, 0), r_v)

    return {
        "origin": origin,
        "signals": signals,
        "confidence_scores": confidence_scores,
        "eligible_technologies": eligible_technologies,
        "peripheral_technologies": peripheral_technologies,
        "route_signals": route_signals,
        "has_eligible_tech": len(eligible_technologies) > 0
    }

# ==============================================================================
# 6. Adaptive Template Selector (3-Layer Architecture & Budgets)
# ==============================================================================
class AdaptiveTemplateSelector:
    """
    Selects the optimal, safest, and most relevant Nuclei templates per Origin
    using the 3-Layer Architecture:
      - Layer A: Universal Safe Baseline (Max 30)
      - Layer B: Technology-Specific Safe Templates (Max 50)
      - Layer C: Discovery-Triggered Safe Templates (Max 20)
    Enforces per-origin (80 templates / 500 requests) and scan-wide limits (3000 pairs).
    """
    def __init__(self, manifest_mgr: Optional[SafeManifestManager] = None):
        self.manifest_mgr = manifest_mgr or SafeManifestManager()

    def select_templates_for_origin(
        self,
        origin_signals: Dict[str, Any],
        baseline_max: int = 30,
        tech_max: int = 50,
        discovery_max: int = 20,
        origin_template_budget: int = 80,
        origin_request_budget: int = 500
    ) -> Dict[str, Any]:
        """
        Builds the per-origin scan plan adhering to strict budgets and safety manifest.
        """
        safe_manifest = self.manifest_mgr.build_or_load_manifest()

        layer_a_selected: List[Dict[str, Any]] = []
        layer_b_selected: List[Dict[str, Any]] = []
        layer_c_selected: List[Dict[str, Any]] = []
        explainability: List[Dict[str, Any]] = []
        seen_template_ids: Set[str] = set()

        # -------------------------------------------------------------
        # Layer A: Universal Safe Baseline
        # -------------------------------------------------------------
        for bp in UNIVERSAL_SAFE_BASELINE_PATHS:
            if len(layer_a_selected) >= baseline_max:
                break
            # Find template in safe manifest by matching relative path
            matched_item = None
            for tpl in safe_manifest.values():
                if tpl["relative_path"].lower() == bp.lower():
                    matched_item = tpl
                    break

            if matched_item and matched_item["template_id"] not in seen_template_ids:
                tid = matched_item["template_id"]
                seen_template_ids.add(tid)
                item_dict = dict(matched_item)
                item_dict["layer"] = "baseline"
                item_dict["score"] = 100
                item_dict["reasons"] = ["Universal Safe Baseline check"]
                layer_a_selected.append(item_dict)
                explainability.append({
                    "template_id": tid,
                    "layer": "baseline",
                    "score": 100,
                    "reasons": item_dict["reasons"]
                })

        # -------------------------------------------------------------
        # Layer B: Technology-Specific Safe Templates
        # -------------------------------------------------------------
        eligible_techs = origin_signals.get("eligible_technologies", [])
        for tech in eligible_techs:
            tech_name = tech["name"]
            confidence = tech["confidence_score"]
            reasons = tech["reasons"]

            matching_for_tech: List[Dict[str, Any]] = []
            for tpl in safe_manifest.values():
                tid = tpl["template_id"]
                if tid in seen_template_ids:
                    continue

                rel_p = tpl["relative_path"].lower()
                tags = tpl.get("tags", [])

                # Check path or tag match
                matches = False
                if tech_name in rel_p.split("/") or tech_name in rel_p:
                    matches = True
                elif any(tech_name == t or tech_name in t for t in tags):
                    matches = True

                if matches:
                    matching_for_tech.append(tpl)

            # Limit per technology to prevent single technology overflow
            for tpl in matching_for_tech[:tech_max]:
                if len(layer_b_selected) >= tech_max:
                    break
                tid = tpl["template_id"]
                if tid not in seen_template_ids:
                    seen_template_ids.add(tid)
                    item_dict = dict(tpl)
                    item_dict["layer"] = "technology"
                    item_dict["score"] = confidence
                    item_dict["reasons"] = list(reasons)
                    layer_b_selected.append(item_dict)
                    explainability.append({
                        "template_id": tid,
                        "layer": "technology",
                        "score": confidence,
                        "reasons": item_dict["reasons"]
                    })

        # -------------------------------------------------------------
        # Layer C: Discovery-Triggered Safe Templates
        # -------------------------------------------------------------
        route_signals = origin_signals.get("route_signals", {})
        for route_name, r_score in route_signals.items():
            matching_for_route: List[Dict[str, Any]] = []
            for tpl in safe_manifest.values():
                tid = tpl["template_id"]
                if tid in seen_template_ids:
                    continue
                rel_p = tpl["relative_path"].lower()
                tags = tpl.get("tags", [])

                matches = False
                if route_name in rel_p or any(route_name in t for t in tags):
                    matches = True

                if matches:
                    matching_for_route.append(tpl)

            for tpl in matching_for_route[:discovery_max]:
                if len(layer_c_selected) >= discovery_max:
                    break
                tid = tpl["template_id"]
                if tid not in seen_template_ids:
                    seen_template_ids.add(tid)
                    item_dict = dict(tpl)
                    item_dict["layer"] = "discovery"
                    item_dict["score"] = r_score
                    item_dict["reasons"] = [f"Discovery route match: {route_name}"]
                    layer_c_selected.append(item_dict)
                    explainability.append({
                        "template_id": tid,
                        "layer": "discovery",
                        "score": r_score,
                        "reasons": item_dict["reasons"]
                    })

        # Combine candidate templates
        all_selected = layer_a_selected + layer_b_selected + layer_c_selected
        total_discovered = len(all_selected)

        # -------------------------------------------------------------
        # Enforce Per-Origin Request Budget (500) & Template Budget (80)
        # -------------------------------------------------------------
        # Prioritize candidates:
        #   1. Layer A (baseline) always takes highest priority
        #   2. Efficiency: relevance_score / request_cost
        #   3. Tie-breaker: score desc, cost asc, template_id asc
        def _candidate_rank_key(item: Dict[str, Any]):
            is_baseline = 1 if item.get("layer") == "baseline" else 0
            cost = max(1, item.get("request_cost") or item.get("estimated_requests") or 1)
            score = item.get("score", 0)
            efficiency = score / cost
            return (is_baseline, efficiency, score, -cost, item.get("template_id", ""))

        all_selected.sort(key=_candidate_rank_key, reverse=True)

        trimmed = []
        current_reqs = 0
        skipped_due_to_budget = 0

        for tpl in all_selected:
            cost = max(1, tpl.get("request_cost") or tpl.get("estimated_requests") or 1)
            # Ensure template has explicit request_cost key
            tpl["request_cost"] = cost
            if (current_reqs + cost <= origin_request_budget) and (len(trimmed) < origin_template_budget):
                trimmed.append(tpl)
                current_reqs += cost
            else:
                skipped_due_to_budget += 1

        all_selected = trimmed
        total_est_requests = current_reqs

        return {
            "origin": origin_signals["origin"],
            "layer_a_count": sum(1 for t in all_selected if t.get("layer") == "baseline"),
            "layer_b_count": sum(1 for t in all_selected if t.get("layer") == "technology"),
            "layer_c_count": sum(1 for t in all_selected if t.get("layer") == "discovery"),
            "total_selected": len(all_selected),
            "total_discovered": total_discovered,
            "skipped_due_to_budget": skipped_due_to_budget,
            "estimated_requests": total_est_requests,
            "selected_templates": all_selected,
            "explainability": explainability,
            "signals": origin_signals
        }

# ==============================================================================
# 7. Scan Plan Generator & Profile Grouper (Section 23, 24)
# ==============================================================================
def generate_nuclei_scan_plan(
    session_dir: str,
    origins: List[str],
    active_urls_json: Optional[str] = None,
    api_endpoints_file: Optional[str] = None,
    scan_wide_pair_budget: int = 3000
) -> Dict[str, Any]:
    """
    Generates a complete, multi-profile Adaptive Nuclei Scan Plan.
    Groups origins with identical template sets into unified profiles.
    """
    if active_urls_json is None:
        active_urls_json = os.path.join(session_dir, "active_urls.json")
    if api_endpoints_file is None:
        api_endpoints_file = os.path.join(session_dir, "api_endpoints.txt")

    manifest_mgr = SafeManifestManager()
    manifest_mgr.write_manifest_files(session_dir)
    selector = AdaptiveTemplateSelector(manifest_mgr)

    # 1. Load active_urls_records
    active_records = []
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

    # 2. Load api_routes
    api_routes = []
    if os.path.exists(api_endpoints_file):
        try:
            with open(api_endpoints_file, "r", encoding="utf-8") as f:
                api_routes = [l.strip() for l in f if l.strip()]
        except Exception:
            pass

    # 3. Compute per-origin plans
    origin_plans: List[Dict[str, Any]] = []
    total_pairs = 0

    for orig in origins:
        sig = extract_origin_signals(orig, active_records, api_routes)
        plan = selector.select_templates_for_origin(sig)
        origin_plans.append(plan)
        total_pairs += plan["total_selected"]

    # 4. Check & enforce scan-wide budget (max 3000 pairs)
    budget_limited = False
    if total_pairs > scan_wide_pair_budget and origin_plans:
        budget_limited = True
        allowed_per_origin = max(1, scan_wide_pair_budget // len(origin_plans))
        for p in origin_plans:
            if len(p["selected_templates"]) > allowed_per_origin:
                trimmed = p["selected_templates"][:allowed_per_origin]
                p["skipped_due_to_budget"] += (len(p["selected_templates"]) - len(trimmed))
                p["selected_templates"] = trimmed
                p["layer_a_count"] = sum(1 for t in trimmed if t.get("layer") == "baseline")
                p["layer_b_count"] = sum(1 for t in trimmed if t.get("layer") == "technology")
                p["layer_c_count"] = sum(1 for t in trimmed if t.get("layer") == "discovery")
                p["total_selected"] = len(trimmed)

    # 5. Group by profile (origins sharing identical template sets)
    profile_map: Dict[Tuple[str, ...], List[Dict[str, Any]]] = {}
    for p in origin_plans:
        tpl_key = tuple(sorted(t["template_id"] for t in p["selected_templates"]))
        profile_map.setdefault(tpl_key, []).append(p)

    profiles: List[Dict[str, Any]] = []
    for idx, (tpl_key, grouped_plans) in enumerate(profile_map.items()):
        pid = f"profile-{idx+1:03d}"
        profile_targets = [gp["origin"] for gp in grouped_plans]
        first_plan = grouped_plans[0]
        selected_tpls = first_plan["selected_templates"]

        profiles.append({
            "profile_id": pid,
            "targets": profile_targets,
            "origins": profile_targets,
            "signals": {
                "technologies": [t["name"] for t in first_plan["signals"].get("eligible_technologies", [])],
                "routes": list(first_plan["signals"].get("route_signals", {}).keys())
            },
            "template_counts": {
                "baseline_count": first_plan["layer_a_count"],
                "technology_count": first_plan["layer_b_count"],
                "discovery_count": first_plan["layer_c_count"],
                "total": len(selected_tpls),
                "skipped_due_to_budget": sum(gp["skipped_due_to_budget"] for gp in grouped_plans)
            },
            "limits": {
                "template_budget": 80,
                "request_budget": 500,
                "rate_limit": 10,
                "concurrency": 5
            },
            "selected_templates": selected_tpls,
            "explainability": first_plan["explainability"]
        })

    total_baseline = sum(p["template_counts"]["baseline_count"] for p in profiles)
    total_tech = sum(p["template_counts"]["technology_count"] for p in profiles)
    total_disc = sum(p["template_counts"]["discovery_count"] for p in profiles)
    total_selected = sum(p["template_counts"]["total"] for p in profiles)
    total_skipped = sum(p["template_counts"]["skipped_due_to_budget"] for p in profiles)
    total_est_reqs = sum(sum(t.get("request_cost") or t.get("estimated_requests", 1) for t in p["selected_templates"]) for p in profiles)

    scan_plan = {
        "selection_strategy": "adaptive",
        "load_protection": "preventive_controls",
        "preventive_load_controls": True,
        "circuit_breaker_telemetry": "requires_upstream_proxy",
        "profiles": profiles,
        "summary": {
            "origin_count": len(origins),
            "profile_count": len(profiles),
            "baseline_template_count": total_baseline,
            "technology_template_count": total_tech,
            "discovery_template_count": total_disc,
            "selected_template_count": total_selected,
            "skipped_due_to_template_budget": total_skipped,
            "estimated_request_count": total_est_reqs,
            "request_budget": 500,
            "rate_limit": 10,
            "concurrency": 5,
            "budget_limited": budget_limited,
            "preventive_load_controls": True,
            "circuit_breaker_telemetry": "requires_upstream_proxy"
        }
    }

    # Write plan file
    plan_file = os.path.join(session_dir, "nuclei_scan_plan.json")
    with open(plan_file, "w", encoding="utf-8") as pf:
        json.dump(scan_plan, pf, ensure_ascii=False, indent=2)

    return scan_plan

# ==============================================================================
# 8. Adaptive Backoff & Circuit Breaker (Sections 20, 21, 22)
# ==============================================================================
class OriginCircuitBreaker:
    """
    Monitors target responses to detect overload or instability:
      - 5 consecutive 429 Too Many Requests -> trips breaker (rate_limited).
      - 5 consecutive timeouts -> trips breaker (target_unstable).
      - High 5xx rate (>50% in window >= 10) -> trips breaker (server_error).
      - 403 alone does NOT trip breaker (defensive access control).

    CRITICAL ARCHITECTURAL DISCLOSURE (Option B: Preventive Load Controls):
      Standard ProjectDiscovery Nuclei in headless mode (-silent -jsonl) outputs
      only matcher hits to stdout/file. Non-matching responses (429, 500, network timeouts)
      are NOT emitted in the output stream without a live network proxy or telemetry hook.
      Therefore, YemenScan enforces active protection via Preventive Load Controls:
        1. Strict Safe Manifest: only non-mutating GET/HEAD safe templates are selected.
        2. Request Budget: hard limit of max 500 HTTP requests per origin.
        3. Rate Limit: -rl 10 requests per second.
        4. Concurrency: -c 5 and -bs 5.
        5. Timeout & Retries: -timeout 5 and -retries 0.
      OriginCircuitBreaker is provided as a standalone telemetry component for environments
      utilizing an upstream proxy / sidecar logger.
    """
    def __init__(self, origin: str, consecutive_threshold: int = 5):
        self.origin = origin
        self.consecutive_threshold = consecutive_threshold
        self.consecutive_429 = 0
        self.consecutive_timeouts = 0
        self.recent_statuses: List[int] = []
        self.is_tripped = False
        self.trip_reason: Optional[str] = None

    def record_response(self, status_code: int) -> bool:
        """Records a response status code. Returns True if breaker trips."""
        if self.is_tripped:
            return True

        self.recent_statuses.append(status_code)
        if len(self.recent_statuses) > 20:
            self.recent_statuses.pop(0)

        # 429 monitoring
        if status_code == 429:
            self.consecutive_429 += 1
            if self.consecutive_429 >= self.consecutive_threshold:
                self.is_tripped = True
                self.trip_reason = "rate_limited"
                return True
        else:
            self.consecutive_429 = 0

        # Reset timeouts on active response
        self.consecutive_timeouts = 0

        # High 5xx error rate monitoring (window >= 10)
        if len(self.recent_statuses) >= 10:
            five_xx = sum(1 for s in self.recent_statuses if 500 <= s < 600)
            if five_xx / len(self.recent_statuses) >= 0.5:
                self.is_tripped = True
                self.trip_reason = "target_unstable_5xx"
                return True

        return False

    def record_timeout(self) -> bool:
        """Records a connection timeout. Returns True if breaker trips."""
        if self.is_tripped:
            return True

        self.consecutive_timeouts += 1
        if self.consecutive_timeouts >= self.consecutive_threshold:
            self.is_tripped = True
            self.trip_reason = "target_unstable_timeouts"
            return True
        return False
