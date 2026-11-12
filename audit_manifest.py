import os
import re
import json
import yaml
from typing import Dict, Any, Tuple, Optional, List

# Regex patterns for fast pre-filtering & analysis
re_unsafe = re.compile(r"unsafe:\s*true", re.IGNORECASE)
re_race = re.compile(r"race:\s*true", re.IGNORECASE)
re_method = re.compile(r"method:\s*([A-Za-z]+)", re.IGNORECASE)
re_raw = re.compile(r"^\s*raw:\s*$", re.MULTILINE | re.IGNORECASE)
re_payloads = re.compile(r"^\s*payloads:\s*$", re.MULTILINE | re.IGNORECASE)
re_flow = re.compile(r"^\s*flow:\s*$", re.MULTILINE | re.IGNORECASE)
re_attack = re.compile(r"attack:\s*([a-zA-Z]+)", re.IGNORECASE)
re_body = re.compile(r"^\s*body:\s*[\'\"]?.+[\'\"]?", re.MULTILINE | re.IGNORECASE)
re_oast = re.compile(r"(interactsh|interact\.sh|oast\.fun|oast\.site|oast\.me|oast\.pro|\{\{interactsh-url\}\})", re.IGNORECASE)

BLOCKED_TAGS = {"intrusive", "dos", "fuzz", "bruteforce", "local"}

REVIEW_TAGS = {
    "sqli", "sql-injection", "rce", "cmi", "cmd-injection", 
    "traversal", "lfi", "rfi", "ssrf", "oast", "interactsh", 
    "xxe", "deserialization", "insecure-deserialization", 
    "auth-bypass", "xss", "default-login", "credential", "brute",
    "file-upload", "upload"
}

BLOCKED_KEYWORDS = [
    "reverse shell", "bind shell", "destructive action", 
    "configuration modification", "password modification", "database modification"
]


def estimate_request_cost(content: str) -> Tuple[Optional[int], str]:
    """
    Statically estimates the HTTP request cost of a Nuclei template.
    Returns (cost, explanation). If cost is unknown or unbounded, returns (None, reason).
    """
    # 1. Check for raw requests
    if re_raw.search(content):
        raw_blocks = re.findall(r"^\s*-\s*\|\s*$", content, re.MULTILINE)
        raw_lines = re.findall(r"^\s*-\s*[\'\"]?(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+", content, re.MULTILINE)
        count = max(len(raw_blocks), len(raw_lines), 1)
        return count, f"{count} raw HTTP request(s)"

    # 2. Check for payloads or attack generator
    has_payloads = bool(re_payloads.search(content))
    attack_m = re_attack.search(content)
    if has_payloads or attack_m:
        # Check if unbounded or contains wordlist / external fuzzing
        if "fuzzing" in content.lower() or "wordlist" in content.lower():
            return None, "Unbounded external payload/wordlist"
        # Try to parse payload items if simple
        payload_items = re.findall(r"^\s*-\s*[\'\"]?[a-zA-Z0-9_\-\.\/]+[\'\"]?\s*$", content, re.MULTILINE)
        if len(payload_items) > 100:
            return None, f"Large or unbounded payload list ({len(payload_items)} items)"
        multiplier = max(1, len(payload_items))
        return multiplier, f"Payload multiplier (~{multiplier} requests)"

    # 3. Standard HTTP requests: count path entries across all blocks
    # Look for list elements starting with {{BaseURL}}, {{RootURL}}, {{Hostname}}, or /
    path_entries = re.findall(r"^\s*-\s*[\'\"]?(?:\{\{(?:BaseURL|RootURL|Hostname)\}\}|\/[a-zA-Z0-9_\-\.\/\?=&%])[^\'\"\n]*", content, re.MULTILINE)
    
    # Also check count of path: keys
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

    # -----------------------------------------------------------------
    # 1. BLOCKED POLICY CHECK
    # -----------------------------------------------------------------
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

    # -----------------------------------------------------------------
    # 2. REVIEW POLICY CHECK
    # -----------------------------------------------------------------
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

    # Status-only vulnerability matcher check for high/critical/medium
    if sev in ("MEDIUM", "HIGH", "CRITICAL"):
        has_word_matcher = ("type: word" in content) or ("type: regex" in content) or ("type: dsl" in content)
        has_status_matcher = "type: status" in content
        if has_status_matcher and not has_word_matcher:
            is_review = True
            review_reasons.append("Status-only vulnerability matcher on high/medium/critical severity")

    # Request cost estimation
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

    # -----------------------------------------------------------------
    # 3. SAFE POLICY
    # -----------------------------------------------------------------
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


def audit_templates():
    http_base = "nuclei_templates_official/http"
    total_files = 0
    safe_templates: Dict[str, Dict[str, Any]] = {}
    review_templates: Dict[str, Dict[str, Any]] = {}
    blocked_templates: Dict[str, Dict[str, Any]] = {}

    for root, _, files in os.walk(http_base):
        for f in files:
            if not f.endswith((".yaml", ".yml")):
                continue
            total_files += 1
            fp = os.path.join(root, f)
            rel_path = os.path.relpath(fp, "nuclei_templates_official").replace("\\", "/")

            with open(fp, "r", encoding="utf-8", errors="replace") as yf:
                content = yf.read()

            item = classify_template_content(content, rel_path=rel_path)
            tid = item["template_id"]

            if item["policy"] == "blocked":
                blocked_templates[tid] = item
            elif item["policy"] == "review":
                review_templates[tid] = item
            else:
                safe_templates[tid] = item

    safe_count = len(safe_templates)
    review_count = len(review_templates)
    blocked_count = len(blocked_templates)
    total = safe_count + review_count + blocked_count

    manifest_data = {
        "stats": {
            "total_evaluated": total_files,
            "total_categorized": total,
            "safe_count": safe_count,
            "review_count": review_count,
            "blocked_count": blocked_count,
            "invariant_holds": (total == total_files == (safe_count + review_count + blocked_count))
        },
        "safe": safe_templates,
        "review": review_templates,
        "blocked": blocked_templates
    }

    cache_path = "nuclei_templates_official/.cache_policy_manifest.json"
    with open(cache_path, "w", encoding="utf-8") as cf:
        json.dump(manifest_data, cf, ensure_ascii=False)

    print("=" * 70)
    print("TEMPLATE POLICY AUDIT & CACHE COMPLETED SUCCESSFULLY")
    print("=" * 70)
    print(f"Total Evaluated: {total_files}")
    print(f"Total Categorized: {total}")
    print(f"Safe Count:     {safe_count}")
    print(f"Review Count:   {review_count}")
    print(f"Blocked Count:  {blocked_count}")
    print(f"Invariant: {total} == {safe_count} + {review_count} + {blocked_count} -> {manifest_data['stats']['invariant_holds']}")
    print(f"Saved Cache: {cache_path}")
    print("=" * 70)

    print("\n--- SAMPLE 10 SAFE TEMPLATES ---")
    for s_id, s in list(safe_templates.items())[:10]:
        print(f"  [SAFE] {s_id} | Cost: {s['request_cost']} | Methods: {s['methods']} | Path: {s['relative_path']}")

    print("\n--- SAMPLE 10 REVIEW TEMPLATES ---")
    for r_id, r in list(review_templates.items())[:10]:
        print(f"  [REVIEW] {r_id} | Reason: {r['reason']} | Path: {r['relative_path']}")

    print("\n--- SAMPLE 10 BLOCKED TEMPLATES ---")
    for b_id, b in list(blocked_templates.items())[:10]:
        print(f"  [BLOCKED] {b_id} | Reason: {b['reason']} | Path: {b['relative_path']}")

    return manifest_data


if __name__ == "__main__":
    audit_templates()
