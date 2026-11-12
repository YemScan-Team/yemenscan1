import os
import json
import socket
import ipaddress
import re
from typing import List, Tuple, Dict, Optional, Any, Set
from concurrent.futures import ThreadPoolExecutor
from core.runner import run_docker_tool
from core.session import update_status
from core.target_prioritizer import prioritize_hosts, prioritize_ports

_HOSTNAME_LABEL_REGEX = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

def is_ip_address(val: str) -> bool:
    """Checks if the given string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False

def normalize_and_validate_subdomain(raw: str, root_domain: str) -> Optional[str]:
    """
    Validates and normalizes a candidate subdomain string discovered by Subfinder.
    Rules:
    - Trim whitespace, lowercase, remove trailing dot.
    - Reject empty values, wildcards (*.domain), URLs (http://..., path /), IP addresses, ports (:8080).
    - Accept valid hostnames only (RFC 1123).
    - Enforce that host belongs to root_domain: host.endswith("." + root_domain)
    - Exclude root_domain itself: host != root_domain.
    """
    if not raw or not isinstance(raw, str):
        return None

    # 1. Normalize root domain
    clean_root = root_domain.strip().lower()
    if "://" in clean_root:
        clean_root = clean_root.split("://", 1)[1]
    clean_root = clean_root.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    if not clean_root:
        return None

    # 2. Trim whitespace, lowercase, remove trailing dot
    candidate = raw.strip().lower().rstrip(".")
    if not candidate:
        return None

    # 3. Reject wildcards
    if "*" in candidate:
        return None

    # 4. Reject URLs, paths, userinfo, colons (ports)
    if "://" in candidate or "/" in candidate or ":" in candidate or "@" in candidate or "\\" in candidate:
        return None

    # 5. Reject IP addresses (IPv4 & IPv6)
    if is_ip_address(candidate):
        return None

    # 6. Reject if it is exactly the root domain
    if candidate == clean_root:
        return None

    # 7. Must end with "." + root_domain
    expected_suffix = "." + clean_root
    if not candidate.endswith(expected_suffix):
        return None

    # 8. Must have at least one valid subdomain prefix before root domain
    subdomain_prefix = candidate[:-len(expected_suffix)]
    if not subdomain_prefix:
        return None

    # 9. Validate all hostname labels (RFC 1123)
    labels = candidate.split(".")
    if len(labels) < 2 or len(candidate) > 253:
        return None

    for label in labels:
        if not label or len(label) > 63:
            return None
        if not _HOSTNAME_LABEL_REGEX.match(label):
            return None

    return candidate

def run_subfinder(domain: str, session_dir: str, scan_id: str) -> Tuple[bool, List[str]]:
    """
    Runs Subfinder to passively enumerate subdomains.
    Outputs raw findings to subfinder_raw.txt, then validates, normalizes,
    and deduplicates findings into subdomains.txt.
    Does not use DNS brute-forcing or default lists, and never considers the root domain as a subdomain.
    """
    # 1. Clean root domain string
    clean_domain = domain.strip().lower()
    if "://" in clean_domain:
        clean_domain = clean_domain.split("://", 1)[1]
    clean_domain = clean_domain.split("/", 1)[0].split(":", 1)[0].rstrip(".")

    print(f"[1/4] جاري البحث عن النطاقات الفرعية (Subfinder Engine) للنطاق: {clean_domain}...", flush=True)
    update_status(
        scan_id,
        stage="phase1_discovery",
        tool="subfinder",
        progress=10,
        log_message=f"بدء استكشاف النطاقات الفرعية السلبي للنطاق: {clean_domain} (Subfinder)..."
    )

    raw_file = os.path.join(session_dir, "subfinder_raw.txt")
    subdomains_file = os.path.join(session_dir, "subdomains.txt")
    meta_file = os.path.join(session_dir, "subfinder_metadata.json")

    # Clean slate: ensure previous scan files are not reused
    for old_file in (raw_file, subdomains_file, meta_file):
        if os.path.exists(old_file):
            try:
                os.remove(old_file)
            except Exception:
                pass

    # Run Subfinder with strict passive enumeration flags
    args = [
        "-d", clean_domain,
        "-silent",
        "-duc",
        "-timeout", "15",
        "-max-time", "3",
        "-o", "/data/subfinder_raw.txt"
    ]

    ok, output = run_docker_tool(
        image="projectdiscovery/subfinder:v2.17.0",
        args=args,
        volume_dir=session_dir,
        timeout=210,
        scan_id=scan_id
    )

    # Handle Subfinder failure: do not fake success or inject fallbacks
    if not ok:
        err_msg = output.strip() if output else "Subfinder tool execution failed"
        print(f"[!] فشل تشغيل Subfinder: {err_msg}", flush=True)
        metadata = {
            "tool": "subfinder",
            "status": "failed",
            "raw_count": 0,
            "valid_count": 0,
            "invalid_count": 0,
            "duplicate_count": 0,
            "error": err_msg
        }
        try:
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(metadata, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        update_status(
            scan_id,
            progress=20,
            log_message=f"فشل استكشاف النطاقات الفرعية (Subfinder): {err_msg}",
            stats_update={"subdomains_count": 0}
        )
        return False, []

    # Ensure raw output file exists as evidence
    if not os.path.exists(raw_file):
        with open(raw_file, "w", encoding="utf-8") as f:
            if output and output.strip():
                f.write(output.strip() + "\n")
            else:
                f.write("")
    elif os.path.getsize(raw_file) == 0 and output and output.strip():
        with open(raw_file, "w", encoding="utf-8") as f:
            f.write(output.strip() + "\n")

    # Read and process raw tool output
    raw_lines: List[str] = []
    if os.path.exists(raw_file):
        with open(raw_file, "r", encoding="utf-8", errors="replace") as f:
            raw_lines = [line.strip() for line in f if line.strip()]

    raw_count = len(raw_lines)
    seen: Set[str] = set()
    valid_subdomains: List[str] = []
    invalid_count = 0
    duplicate_count = 0

    for line in raw_lines:
        norm = normalize_and_validate_subdomain(line, clean_domain)
        if not norm:
            invalid_count += 1
            continue

        if norm in seen:
            duplicate_count += 1
            continue

        seen.add(norm)
        valid_subdomains.append(norm)

    # Sort discovered subdomains without injecting the root domain
    valid_subdomains = prioritize_hosts(valid_subdomains, clean_domain, include_root=False)

    # valid_count must always match the actual count of subdomains written to subdomains.txt
    valid_count = len(valid_subdomains)

    # Write cleaned subdomains to subdomains.txt
    with open(subdomains_file, "w", encoding="utf-8") as f:
        for s in valid_subdomains:
            f.write(f"{s}\n")

    # Save tool execution metadata
    metadata = {
        "tool": "subfinder",
        "status": "completed",
        "raw_count": raw_count,
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "duplicate_count": duplicate_count
    }
    try:
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    # Print discovered subdomains directly to stdout
    for s in valid_subdomains:
        print(s, flush=True)
    if valid_subdomains:
        print("", flush=True)

    update_status(
        scan_id,
        progress=20,
        log_message=f"اكتمل استكشاف النطاقات الفرعية: تم العثور على {valid_count} نطاق فرعي بواسطة Subfinder.",
        stats_update={"subdomains_count": valid_count}
    )

    return True, valid_subdomains

NAABU_PORTS = "80,443,8080,8443,8000,8081,8888,9000,3000,5000,7001,9090"
SCANNED_PORTS = [80, 443, 8080, 8443, 8000, 8081, 8888, 9000, 3000, 5000, 7001, 9090]

def normalize_target_host(target: str) -> Optional[str]:
    """
    Normalizes a target hostname or IP address:
    - Strips whitespace
    - Lowercases
    - Strips URL schemes, paths, and colons if accidentally present
    - Strips trailing dots (e.g. API.Example.COM. -> api.example.com)
    """
    if not target or not isinstance(target, str):
        return None
    t = target.strip().lower()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    return t if t else None

def _test_tcp_port(host: str, port: int) -> bool:
    """Fast non-blocking socket test to check if a TCP port is open (retained for backward compatibility)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.75)
            res = s.connect_ex((host, port))
            return res == 0
    except Exception:
        return False

def _resolve_host_entry(clean_s: str) -> Tuple[str, str]:
    """Helper to resolve host to IP (retained for backward compatibility)."""
    try:
        ip = socket.gethostbyname(clean_s)
        return clean_s, ip
    except Exception:
        return clean_s, ""

def run_naabu(subdomains: List[str], session_dir: str, scan_id: str) -> Tuple[bool, List[str]]:
    """
    Runs Naabu to discover open ports across enumerated targets.
    Reads current execution targets without reusing stale targets files or injecting synthetic DNS mappings.
    Outputs: naabu_raw.jsonl (evidence), ports.txt (validated host:port), and naabu_metadata.json.
    """
    print("[2/4] جاري فحص المنافذ المفتوحة (Naabu Engine)...", flush=True)
    update_status(
        scan_id,
        stage="phase1_discovery",
        tool="naabu",
        progress=25,
        log_message="بدء فحص المنافذ المفتوحة القياسية وغير القياسية (Naabu)...",
        stats_update={"open_ports_count": 0}
    )

    ports_file = os.path.join(session_dir, "ports.txt")
    naabu_targets_file = os.path.join(session_dir, "naabu_targets.txt")
    raw_file = os.path.join(session_dir, "naabu_raw.jsonl")
    meta_file = os.path.join(session_dir, "naabu_metadata.json")

    # Clean slate: clear prior execution artifacts for Naabu only (including stale naabu_targets.txt)
    for f_path in (raw_file, ports_file, meta_file, naabu_targets_file):
        if os.path.exists(f_path):
            try:
                os.remove(f_path)
            except Exception:
                pass

    # Normalize and deduplicate input targets for current execution, preserving order of first appearance
    seen_targets: Set[str] = set()
    valid_targets: List[str] = []
    for s in (subdomains or []):
        norm = normalize_target_host(s)
        if norm and norm not in seen_targets:
            seen_targets.add(norm)
            valid_targets.append(norm)

    # Write naabu_targets.txt strictly from current valid targets
    if valid_targets:
        with open(naabu_targets_file, "w", encoding="utf-8") as f:
            for t in valid_targets:
                f.write(f"{t}\n")
    else:
        # Zero targets provided: valid run with zero ports, do not run Naabu or reuse previous targets
        metadata = {
            "tool": "naabu",
            "status": "completed",
            "input_count": 0,
            "raw_count": 0,
            "valid_count": 0,
            "invalid_count": 0,
            "duplicate_count": 0,
            "open_endpoint_count": 0,
            "unique_port_count": 0,
            "scanned_ports": SCANNED_PORTS,
            "engine": "naabu",
            "version": "v2.6.1"
        }
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)

        with open(ports_file, "w", encoding="utf-8") as f:
            pass

        update_status(
            scan_id,
            progress=35,
            log_message="اكتمل فحص المنافذ: لم يتم تحديد أهداف للفحص (0 منافذ).",
            tool_status={"naabu": "empty"},
            stats_update={"open_ports_count": 0}
        )
        return True, []

    # Calculate timeout based on target volume (min 240 seconds)
    calc_timeout = max(240, len(valid_targets) * 5)

    args = [
        "-list", "/data/naabu_targets.txt",
        "-silent",
        "-p", NAABU_PORTS,
        "-s", "c",
        "-duc",
        "-iv", "4",
        "-timeout", "1s",
        "-retries", "1",
        "-rate", "300",
        "-verify",
        "-json",
        "-o", "/data/naabu_raw.jsonl"
    ]

    ok, output = run_docker_tool(
        image="projectdiscovery/naabu:v2.6.1",
        args=args,
        volume_dir=session_dir,
        timeout=calc_timeout,
        scan_id=scan_id
    )

    # Handle Naabu failure: do not fabricate fallback open ports
    if not ok:
        err_msg = output.strip() if output else "Naabu tool execution failed"
        print(f"[!] فشل تشغيل Naabu: {err_msg}", flush=True)
        metadata = {
            "tool": "naabu",
            "status": "failed",
            "input_count": len(valid_targets),
            "raw_count": 0,
            "valid_count": 0,
            "invalid_count": 0,
            "duplicate_count": 0,
            "open_endpoint_count": 0,
            "unique_port_count": 0,
            "scanned_ports": SCANNED_PORTS,
            "engine": "naabu",
            "version": "v2.6.1",
            "error": err_msg
        }
        try:
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(metadata, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        update_status(
            scan_id,
            progress=35,
            log_message=f"فشل فحص المنافذ بواسطة Naabu: {err_msg}",
            tool_status={"naabu": "failed"},
            stats_update={"open_ports_count": 0}
        )
        return False, []

    # Ensure raw output file exists as evidence
    if not os.path.exists(raw_file):
        with open(raw_file, "w", encoding="utf-8") as f:
            if output and output.strip():
                f.write(output.strip() + "\n")
            else:
                f.write("")
    elif os.path.getsize(raw_file) == 0 and output and output.strip():
        with open(raw_file, "w", encoding="utf-8") as f:
            f.write(output.strip() + "\n")

    # Read and parse raw JSONL output line by line
    raw_lines: List[str] = []
    if os.path.exists(raw_file):
        with open(raw_file, "r", encoding="utf-8", errors="replace") as f:
            raw_lines = [line.strip() for line in f if line.strip()]

    raw_count = len(raw_lines)
    seen_endpoints: Set[Tuple[str, int]] = set()
    discovered_ports: List[str] = []
    invalid_count = 0
    duplicate_count = 0

    for line in raw_lines:
        try:
            data = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            invalid_count += 1
            continue

        if not isinstance(data, dict):
            invalid_count += 1
            continue

        # Extract host or ip directly from Naabu without arbitrary mapping
        # Prefer the actual host if present, non-empty, and valid
        host_val = data.get("host")
        ip_val = data.get("ip")

        target_host = ""
        if host_val and isinstance(host_val, str) and host_val.strip():
            candidate = host_val.strip().rstrip(".").lower()
            if ":" in candidate:
                candidate = candidate.split(":", 1)[0]
            if candidate:
                target_host = candidate

        # Fallback to IP if host is absent, empty, or IP-only JSON
        if not target_host and ip_val and isinstance(ip_val, str) and ip_val.strip():
            candidate = ip_val.strip()
            if ":" in candidate:
                candidate = candidate.split(":", 1)[0]
            if candidate:
                target_host = candidate

        if not target_host:
            invalid_count += 1
            continue

        port_raw = data.get("port")
        try:
            port_num = int(port_raw)
            if not (1 <= port_num <= 65535):
                invalid_count += 1
                continue
        except (ValueError, TypeError):
            invalid_count += 1
            continue

        canonical_key = (target_host.lower(), port_num)
        if canonical_key in seen_endpoints:
            duplicate_count += 1
            continue

        seen_endpoints.add(canonical_key)
        discovered_ports.append(f"{target_host}:{port_num}")

    # Prioritize ports for primary target at top without creating synthetic ports
    root_domain = valid_targets[0] if valid_targets else ""
    discovered_ports = prioritize_ports(discovered_ports, root_domain)

    valid_count = len(discovered_ports)
    open_endpoint_count = valid_count
    unique_ports = {int(p.split(":")[-1]) for p in discovered_ports if ":" in p}
    unique_port_count = len(unique_ports)

    # Save final verified ports
    with open(ports_file, "w", encoding="utf-8") as f:
        for p in discovered_ports:
            f.write(f"{p}\n")

    # Write Naabu metadata
    metadata = {
        "tool": "naabu",
        "status": "completed",
        "input_count": len(valid_targets),
        "raw_count": raw_count,
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "duplicate_count": duplicate_count,
        "open_endpoint_count": open_endpoint_count,
        "unique_port_count": unique_port_count,
        "scanned_ports": SCANNED_PORTS,
        "engine": "naabu",
        "version": "v2.6.1"
    }
    try:
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    # Print discovered ports directly to stdout
    for p in discovered_ports:
        print(p, flush=True)
    if discovered_ports:
        print("", flush=True)

    if open_endpoint_count > 0:
        log_msg = f"اكتمل فحص المنافذ: تم اكتشاف {open_endpoint_count} نقطة نهاية مفتوحة ({unique_port_count} منفذاً فريداً) بواسطة Naabu."
        tool_res = "success"
    else:
        log_msg = "اكتمل فحص المنافذ: لم يتم اكتشاف أي منافذ مفتوحة بواسطة Naabu (0 منافذ)."
        tool_res = "empty"

    update_status(
        scan_id,
        progress=35,
        log_message=log_msg,
        tool_status={"naabu": tool_res},
        stats_update={"open_ports_count": open_endpoint_count}
    )

    return True, discovered_ports
