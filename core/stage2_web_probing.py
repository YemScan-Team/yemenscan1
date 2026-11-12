import os
import json
import time
import re
import shutil
import hashlib
from urllib.parse import urlsplit
from typing import List, Dict, Any, Tuple, Optional, Set
import requests
from core.runner import run_docker_tool, run_local_tool, is_scan_cancelled, ScanCancelledException
from core.session import update_status, get_status
from core.target_prioritizer import prioritize_urls, prioritize_dict_records

# Kiterunner official constants
KITERUNNER_WORDLIST_NAME = "routes-small.kite"
KITERUNNER_WORDLIST_SHA256 = "2b1bcac8666580c15cc763dd41a2360553439b729b6234679f5f05bdd10cb514"
KITERUNNER_UPSTREAM_VERSION = "v1.0.2"
KITERUNNER_UPSTREAM_COMMIT = "e7a7fa6"
KITERUNNER_BUILD_VARIANT = "yemscan1"
KITERUNNER_PATCHES = ["remove-default-x-forwarded-for"]
KITERUNNER_DOCKER_IMAGE = "yemscan/kiterunner:v1.0.2-yemscan1"

def normalize_host_port(entry: str) -> Optional[str]:
    """
    Normalizes a host:port string:
    - Strips whitespace
    - Validates presence of ':' separating host and port
    - Lowercases host and removes trailing dots
    - Validates port is an integer between 1 and 65535
    Returns normalized 'host:port' or None if malformed.
    """
    if not entry or not isinstance(entry, str):
        return None
    clean = entry.strip()
    if ":" not in clean:
        return None
    parts = clean.rsplit(":", 1)
    host = parts[0].strip().lower().rstrip(".")
    port_str = parts[1].strip()
    if not host or not port_str:
        return None
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].rstrip(".")
    if not host:
        return None
    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            return None
    except ValueError:
        return None
    return f"{host}:{port}"

def normalize_web_url(raw_url: str) -> Optional[str]:
    """
    Normalizes a web service URL:
    - Scheme must be http or https
    - Lowercase hostname and strip trailing dots
    - Remove default ports (:80 for http, :443 for https)
    - Preserve non-default ports (:8080, :8443, etc.)
    - Retain path (without trailing slash unless root) and query if present
    """
    if not raw_url or not isinstance(raw_url, str):
        return None
    raw = raw_url.strip()
    try:
        parsed = urlsplit(raw)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return None
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return None
        port = parsed.port
        if port:
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                port_str = ""
            else:
                port_str = f":{port}"
        else:
            port_str = ""
        path = parsed.path.rstrip("/") if parsed.path and parsed.path != "/" else parsed.path
        if path == "/":
            path = ""
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{host}{port_str}{path}{query}"
    except Exception:
        return None

def run_httpx(session_dir: str, scan_id: str) -> Tuple[bool, List[Dict[str, Any]], List[str]]:
    """
    Runs HTTPX on discovered ports (from ports.txt) to identify live HTTP/HTTPS servers.
    Does not invent default URLs, synthetic status codes, or use Python requests fallbacks.
    Outputs: httpx_input.txt, httpx_raw.jsonl, active_urls.json, active_urls.txt, httpx_metadata.json.
    """
    print("[3/4] جاري فحص الخدمات النشطة (HTTPX)...", flush=True)
    update_status(
        scan_id,
        stage="phase2_web_probing",
        tool="httpx",
        progress=45,
        log_message="التحقق من خدمات الويب النشطة وبصمات التقنيات (HTTPX)...",
        stats_update={"live_urls_count": 0}
    )

    ports_file = os.path.join(session_dir, "ports.txt")
    httpx_input_file = os.path.join(session_dir, "httpx_input.txt")
    httpx_raw_file = os.path.join(session_dir, "httpx_raw.jsonl")
    active_urls_json = os.path.join(session_dir, "active_urls.json")
    active_urls_txt = os.path.join(session_dir, "active_urls.txt")
    meta_file = os.path.join(session_dir, "httpx_metadata.json")

    # Clean slate: clear prior execution artifacts for httpx only
    for f_path in (httpx_input_file, httpx_raw_file, active_urls_json, active_urls_txt, meta_file):
        if os.path.exists(f_path):
            try:
                os.remove(f_path)
            except Exception:
                pass

    # Read and normalize host:port targets strictly from ports.txt
    raw_ports: List[str] = []
    if os.path.exists(ports_file):
        with open(ports_file, "r", encoding="utf-8", errors="replace") as pf:
            raw_ports = [line.strip() for line in pf if line.strip()]

    seen_inputs: Set[str] = set()
    valid_inputs: List[str] = []
    valid_input_endpoints: Set[Tuple[str, int]] = set()
    for p in raw_ports:
        norm = normalize_host_port(p)
        if norm and norm not in seen_inputs:
            seen_inputs.add(norm)
            valid_inputs.append(norm)
            h_part, p_part = norm.rsplit(":", 1)
            valid_input_endpoints.add((h_part.lower().rstrip("."), int(p_part)))

    if not valid_inputs:
        metadata = {
            "tool": "httpx",
            "status": "completed",
            "input_count": 0,
            "raw_count": 0,
            "valid_count": 0,
            "invalid_count": 0,
            "duplicate_count": 0,
            "protocol_mismatch_count": 0,
            "live_service_count": 0,
            "unique_host_count": 0,
            "scheme_counts": {"http": 0, "https": 0},
            "status_code_counts": {},
            "engine": "httpx",
            "version": "v1.12.0"
        }
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)

        with open(active_urls_json, "w", encoding="utf-8") as f:
            pass
        with open(active_urls_txt, "w", encoding="utf-8") as f:
            pass

        update_status(
            scan_id,
            progress=55,
            log_message="اكتمل فحص خدمات الويب: لم يتم العثور على منافذ مفتوحة لفحصها (0 عناوين).",
            tool_status={"httpx": "empty"},
            stats_update={"live_urls_count": 0}
        )
        return True, [], []

    # Write httpx_input.txt strictly from valid_inputs
    with open(httpx_input_file, "w", encoding="utf-8") as f:
        for inp in valid_inputs:
            f.write(f"{inp}\n")

    calc_timeout = max(180, len(valid_inputs) * 3)

    args = [
        "-l", "/data/httpx_input.txt",
        "-silent",
        "-title",
        "-tech-detect",
        "-status-code",
        "-content-length",
        "-web-server",
        "-location",
        "-duc",
        "-timeout", "5",
        "-retries", "1",
        "-nf",
        "-json",
        "-o", "/data/httpx_raw.jsonl"
    ]

    ok, output = run_docker_tool(
        image="projectdiscovery/httpx:v1.12.0",
        args=args,
        volume_dir=session_dir,
        timeout=calc_timeout,
        scan_id=scan_id
    )

    if not ok:
        err_msg = output.strip() if output else "HTTPX tool execution failed"
        print(f"[!] فشل تشغيل HTTPX: {err_msg}", flush=True)
        metadata = {
            "tool": "httpx",
            "status": "failed",
            "input_count": len(valid_inputs),
            "raw_count": 0,
            "valid_count": 0,
            "invalid_count": 0,
            "duplicate_count": 0,
            "protocol_mismatch_count": 0,
            "live_service_count": 0,
            "unique_host_count": 0,
            "scheme_counts": {"http": 0, "https": 0},
            "status_code_counts": {},
            "engine": "httpx",
            "version": "v1.12.0",
            "error": err_msg
        }
        try:
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(metadata, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        update_status(
            scan_id,
            progress=55,
            log_message=f"فشل فحص خدمات الويب بواسطة HTTPX: {err_msg}",
            tool_status={"httpx": "failed"},
            stats_update={"live_urls_count": 0}
        )
        return False, [], []

    # Ensure raw output file exists as evidence
    if not os.path.exists(httpx_raw_file):
        with open(httpx_raw_file, "w", encoding="utf-8") as f:
            if output and output.strip():
                f.write(output.strip() + "\n")
            else:
                f.write("")
    elif os.path.getsize(httpx_raw_file) == 0 and output and output.strip():
        with open(httpx_raw_file, "w", encoding="utf-8") as f:
            f.write(output.strip() + "\n")

    # Read and parse raw JSONL output line by line
    raw_lines: List[str] = []
    if os.path.exists(httpx_raw_file):
        with open(httpx_raw_file, "r", encoding="utf-8", errors="replace") as f:
            raw_lines = [line.strip() for line in f if line.strip()]

    raw_count = len(raw_lines)
    seen_urls: Set[str] = set()
    web_targets: List[Dict[str, Any]] = []
    active_urls: List[str] = []
    invalid_count = 0
    duplicate_count = 0
    protocol_mismatch_count = 0
    scheme_counts = {"http": 0, "https": 0}
    status_code_counts: Dict[str, int] = {}
    unique_hosts: Set[str] = set()

    for line in raw_lines:
        try:
            data = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            invalid_count += 1
            continue

        if not isinstance(data, dict):
            invalid_count += 1
            continue

        raw_url = data.get("url")
        norm_url = normalize_web_url(raw_url)
        if not norm_url:
            invalid_count += 1
            continue

        parsed = urlsplit(norm_url)
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or scheme not in ("http", "https"):
            invalid_count += 1
            continue

        port = parsed.port or (443 if scheme == "https" else 80)
        url_endpoint = (host, port)

        # Provenance Check 1: Extracted URL endpoint must match valid_input_endpoints
        if url_endpoint not in valid_input_endpoints:
            invalid_count += 1
            continue

        # Provenance Check 2: If "input" field is present, verify its correlation
        raw_input = data.get("input")
        if raw_input:
            norm_inp = normalize_host_port(str(raw_input))
            if norm_inp:
                inp_h, inp_p_str = norm_inp.rsplit(":", 1)
                inp_endpoint = (inp_h.lower().rstrip("."), int(inp_p_str))
                if inp_endpoint not in valid_input_endpoints or inp_endpoint != url_endpoint:
                    invalid_count += 1
                    continue
            else:
                # If input does not contain a port (e.g. host only or scheme://host)
                clean_inp_h = str(raw_input).strip().lower().rstrip(".")
                if "://" in clean_inp_h:
                    clean_inp_h = clean_inp_h.split("://", 1)[1]
                clean_inp_h = clean_inp_h.split("/", 1)[0].rstrip(".")
                if clean_inp_h != host:
                    invalid_count += 1
                    continue

        status_code = data.get("status_code")
        title = str(data.get("title") or "").strip().lower()

        # Check for protocol mismatch (plain HTTP request sent to HTTPS port)
        if (
            scheme == "http"
            and status_code == 400
            and any(phrase in title for phrase in [
                "plain http request was sent to https port",
                "sent to https port"
            ])
        ):
            protocol_mismatch_count += 1
            continue

        if norm_url in seen_urls:
            duplicate_count += 1
            continue

        seen_urls.add(norm_url)
        unique_hosts.add(host)
        scheme_counts[scheme] = scheme_counts.get(scheme, 0) + 1
        if status_code is not None:
            sc_str = str(status_code)
            status_code_counts[sc_str] = status_code_counts.get(sc_str, 0) + 1

        active_urls.append(norm_url)
        web_targets.append({
            "url": norm_url,
            "input": data.get("input") or f"{host}:{port}",
            "scheme": scheme,
            "host": host,
            "port": port,
            "status_code": status_code,
            "title": data.get("title") or "",
            "webserver": data.get("webserver") or "",
            "tech": data.get("tech") or [],
            "content_length": data.get("content_length"),
            "location": data.get("location") or None,
            "source": "httpx"
        })

    stat = get_status(scan_id) or {}
    dom = stat.get("target_domain", "")

    # Prioritize primary entered target at top of output lists without fabricating new URLs
    active_urls = prioritize_urls(active_urls, dom)
    web_targets = prioritize_dict_records(web_targets, dom, key="url")

    valid_count = len(active_urls)
    live_service_count = valid_count

    # Save active_urls.json (one JSON record per line)
    with open(active_urls_json, "w", encoding="utf-8") as f:
        for wt in web_targets:
            f.write(json.dumps(wt, ensure_ascii=False) + "\n")

    # Save active_urls.txt (one URL per line)
    with open(active_urls_txt, "w", encoding="utf-8") as f:
        for u in active_urls:
            f.write(f"{u}\n")

    metadata = {
        "tool": "httpx",
        "status": "completed",
        "input_count": len(valid_inputs),
        "raw_count": raw_count,
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "duplicate_count": duplicate_count,
        "protocol_mismatch_count": protocol_mismatch_count,
        "live_service_count": live_service_count,
        "unique_host_count": len(unique_hosts),
        "scheme_counts": scheme_counts,
        "status_code_counts": status_code_counts,
        "engine": "httpx",
        "version": "v1.12.0"
    }
    try:
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    # Print discovered URLs directly to stdout
    for u in active_urls:
        print(u, flush=True)
    if active_urls:
        print("", flush=True)

    if live_service_count > 0:
        log_msg = f"اكتمل فحص خدمات الويب: تم العثور على {live_service_count} خدمة ويب نشطة بواسطة HTTPX."
        tool_status = "success"
    else:
        log_msg = "اكتمل فحص خدمات الويب: لم يتم العثور على خدمات ويب نشطة بواسطة HTTPX (0 عناوين)."
        tool_status = "empty"

    update_status(
        scan_id,
        progress=55,
        log_message=log_msg,
        tool_status={"httpx": tool_status},
        stats_update={"live_urls_count": live_service_count}
    )

    return True, web_targets, active_urls

def normalize_kiterunner_input(raw_url: str) -> Optional[Tuple[str, Tuple[str, str, int]]]:
    """
    Normalizes an active URL for Kiterunner input.
    Validates scheme (http/https), resolves lowercase hostname and effective port.
    Returns (clean_target_url, (scheme, host, effective_port)) or None if invalid.
    """
    if not raw_url or not isinstance(raw_url, str):
        return None
    clean = raw_url.strip()
    if not clean:
        return None
    try:
        p = urlsplit(clean)
        scheme = p.scheme.lower()
        if scheme not in ("http", "https"):
            return None
        host = p.hostname
        if not host:
            return None
        host = host.lower().rstrip(".")
        if not host:
            return None
        effective_port = p.port or (443 if scheme == "https" else 80)
        if (scheme == "http" and effective_port == 80) or (scheme == "https" and effective_port == 443):
            netloc = host
        else:
            netloc = f"{host}:{effective_port}"
        clean_target = f"{scheme}://{netloc}"
        return clean_target, (scheme, host, effective_port)
    except Exception:
        return None

def normalize_endpoint_url(raw_url: str) -> Optional[Tuple[str, str, Tuple[str, str, int]]]:
    """
    Normalizes a discovered endpoint URL candidate.
    Returns (normalized_full_url, clean_path, (scheme, host, effective_port)) or None.
    """
    if not raw_url or not isinstance(raw_url, str):
        return None
    clean = raw_url.strip()
    if not clean:
        return None
    try:
        p = urlsplit(clean)
        scheme = p.scheme.lower()
        if scheme not in ("http", "https"):
            return None
        host = p.hostname
        if not host:
            return None
        host = host.lower().rstrip(".")
        if not host:
            return None
        effective_port = p.port or (443 if scheme == "https" else 80)
        if (scheme == "http" and effective_port == 80) or (scheme == "https" and effective_port == 443):
            netloc = host
        else:
            netloc = f"{host}:{effective_port}"

        raw_path = p.path or "/"
        parts = [seg for seg in raw_path.split("/") if seg]
        clean_path = "/" + "/".join(parts)
        if raw_path.endswith("/") and clean_path != "/":
            clean_path += "/"

        query = f"?{p.query}" if p.query else ""
        norm_url = f"{scheme}://{netloc}{clean_path}{query}"
        return norm_url, clean_path, (scheme, host, effective_port)
    except Exception:
        return None

def run_kiterunner_or_api_probing(
    active_urls: List[str],
    session_dir: str,
    scan_id: str,
    custom_wordlist: Optional[str] = None
) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Executes official Assetnote Kiterunner (kr scan) inside Docker across live web services.
    Finds real API route candidates using routes-small.kite without fake Python probing.
    Enforces strict provenance against verified active URLs and stores raw evidence.
    """
    kiterunner_input_file = os.path.join(session_dir, "kiterunner_input.txt")
    kiterunner_raw_file = os.path.join(session_dir, "kiterunner_raw.jsonl")
    kiterunner_stderr_file = os.path.join(session_dir, "kiterunner_stderr.log")
    kiterunner_metadata_file = os.path.join(session_dir, "kiterunner_metadata.json")
    api_endpoints_file = os.path.join(session_dir, "api_endpoints.txt")
    api_endpoints_json = os.path.join(session_dir, "api_endpoints.json")

    # Clean slate: remove old Kiterunner stage artifacts
    for old_file in [
        kiterunner_input_file,
        kiterunner_raw_file,
        os.path.join(session_dir, "kiterunner_raw.json"),
        kiterunner_stderr_file,
        kiterunner_metadata_file,
        api_endpoints_file,
        api_endpoints_json
    ]:
        if os.path.exists(old_file):
            try:
                os.remove(old_file)
            except Exception:
                pass

    wordlist_param = f"/opt/kiterunner/{KITERUNNER_WORDLIST_NAME}"
    used_wordlist_sha256 = KITERUNNER_WORDLIST_SHA256
    if custom_wordlist and os.path.exists(custom_wordlist):
        dest_wordlist = os.path.join(session_dir, "custom_wordlist.kite")
        try:
            os.makedirs(session_dir, exist_ok=True)
            shutil.copyfile(custom_wordlist, dest_wordlist)
            wordlist_param = "/data/custom_wordlist.kite"
            with open(custom_wordlist, "rb") as wf:
                used_wordlist_sha256 = hashlib.sha256(wf.read()).hexdigest()
        except Exception as e:
            print(f"[!] Warning copying custom wordlist: {e}", flush=True)
            wordlist_param = f"/opt/kiterunner/{KITERUNNER_WORDLIST_NAME}"
            used_wordlist_sha256 = KITERUNNER_WORDLIST_SHA256

    # Source active URLs from parameter or active_urls.txt
    current_active = list(active_urls) if active_urls else []
    active_urls_txt = os.path.join(session_dir, "active_urls.txt")
    if not current_active and os.path.exists(active_urls_txt):
        try:
            with open(active_urls_txt, "r", encoding="utf-8", errors="replace") as f:
                current_active = [line.strip() for line in f if line.strip()]
        except Exception:
            current_active = []

    # Target normalization, validation and deduplication (preserving order)
    valid_inputs: List[str] = []
    seen_inputs: Set[str] = set()
    valid_input_origins: Set[Tuple[str, str, int]] = set()

    for u in current_active:
        norm_res = normalize_kiterunner_input(u)
        if norm_res:
            target_url, origin_tuple = norm_res
            valid_input_origins.add(origin_tuple)
            if target_url not in seen_inputs:
                seen_inputs.add(target_url)
                valid_inputs.append(target_url)

    # Empty Input Handling: If no verified active URLs, exit immediately without testing root domain fallback
    if not valid_inputs:
        with open(api_endpoints_json, "w", encoding="utf-8") as f:
            json.dump([], f, ensure_ascii=False, indent=2)
        with open(api_endpoints_file, "w", encoding="utf-8") as f:
            pass

        empty_metadata = {
            "tool": "kiterunner",
            "status": "completed",
            "input_count": 0,
            "raw_event_count": 0,
            "parsed_event_count": 0,
            "invalid_event_count": 0,
            "response_record_count": 0,
            "valid_count": 0,
            "invalid_response_count": 0,
            "duplicate_count": 0,
            "candidate_count": 0,
            "unique_origin_count": 0,
            "methods": {},
            "status_code_counts": {},
            "engine": "kiterunner",
            "upstream_version": KITERUNNER_UPSTREAM_VERSION,
            "upstream_commit": KITERUNNER_UPSTREAM_COMMIT,
            "build_variant": KITERUNNER_BUILD_VARIANT,
            "patches": KITERUNNER_PATCHES,
            "wordlist": os.path.basename(wordlist_param),
            "wordlist_sha256": used_wordlist_sha256
        }
        try:
            with open(kiterunner_metadata_file, "w", encoding="utf-8") as f:
                json.dump(empty_metadata, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        update_status(
            scan_id,
            progress=70,
            log_message="اكتمل استكشاف الـ APIs: لم يتم العثور على عناوين ويب نشطة لفحصها (0 مسارات).",
            tool_status={"kiterunner": "empty"},
            stats_update={"api_endpoints_count": 0}
        )
        return True, []

    targets_for_scan = list(valid_inputs)

    # When target list is large (> 12 hosts), apply smart ASM prioritization and deduplication
    if len(targets_for_scan) > 12:
        dom = ""
        status_file = os.path.join(session_dir, "status.json")
        if os.path.exists(status_file):
            try:
                with open(status_file, "r", encoding="utf-8") as sf:
                    dom = json.load(sf).get("target_domain", "")
            except Exception:
                pass
        clean_dom = dom.split(":")[0].strip().lower() if dom else ""

        # 1. Deduplicate by hostname, preferring HTTPS on standard port 443 over redundant HTTP/alternate ports
        by_host: Dict[str, str] = {}
        for u in targets_for_scan:
            p = urlsplit(u)
            h = (p.hostname or "").lower()
            sch = (p.scheme or "").lower()
            port = p.port or (443 if sch == "https" else 80)
            if not h:
                continue
            if h not in by_host:
                by_host[h] = u
            else:
                curr_p = urlsplit(by_host[h])
                curr_sch = (curr_p.scheme or "").lower()
                curr_port = curr_p.port or (443 if curr_sch == "https" else 80)
                if sch == "https" and curr_sch == "http":
                    by_host[h] = u
                elif sch == curr_sch:
                    if (sch == "https" and port == 443 and curr_port != 443):
                        by_host[h] = u
                    elif (sch == "http" and port == 80 and curr_port != 80):
                        by_host[h] = u

        deduped = list(by_host.values())

        # 2. Score candidate relevance for API route fuzzing
        def _api_target_score(url_str: str) -> Tuple[int, int]:
            p = urlsplit(url_str)
            h = (p.hostname or "").lower()
            cdn_keys = ("cdn", "assets", "static", "images", "media", "storage", "analytics", "linkedin", "mail")
            api_keys = ("api", "rest", "graphql", "gateway", "backend", "v1", "v2", "auth", "oauth", "sso", "app")
            app_keys = ("portal", "admin", "dev", "stage", "service", "account", "profile", "labs", "academy")

            if any(k in h for k in cdn_keys) or (clean_dom and h.endswith("-cdn." + clean_dom)):
                tier = 99
            elif any(k in h.split(".") for k in api_keys) or any(k in h for k in ("api.", ".api", "gateway", "backend", "rest", "graphql")):
                tier = 0
            elif clean_dom and (h == clean_dom or h == f"www.{clean_dom}"):
                tier = 1
            elif any(k in h for k in app_keys):
                tier = 2
            else:
                tier = 3
            return (tier, len(url_str))

        pruned_sorted = sorted(deduped, key=_api_target_score)
        targets_for_scan = pruned_sorted[:10]

    # Write normalized input file for Kiterunner
    with open(kiterunner_input_file, "w", encoding="utf-8") as f:
        for inp in targets_for_scan:
            f.write(f"{inp}\n")

    print("[*] جاري استكشاف مسارات الـ APIs الحقيقية (Assetnote Kiterunner)...", flush=True)
    update_status(
        scan_id,
        stage="phase2_web_probing",
        tool="kiterunner",
        progress=60,
        log_message=f"بدء فحص مسارات الـ APIs عبر Kiterunner ضد {len(targets_for_scan)} عنوان ويب نشط...",
        tool_status={"kiterunner": "running"},
        stats_update={"api_endpoints_count": 0}
    )

    if is_scan_cancelled(scan_id):
        raise ScanCancelledException(f"Scan {scan_id} cancelled.")

    # Kiterunner CLI arguments inside Docker
    # Note: Default X-Forwarded-For header is eliminated in the pinned yemscan/kiterunner:v1.0.2-yemscan1 image
    args = [
        "scan",
        "/data/kiterunner_input.txt",
        "-w", wordlist_param,
        "-x", "10",
        "-j", "20",
        "--max-redirects", "0",
        "-d", "1",
        "--quarantine-threshold", "10",
        "--disable-precheck",
        "--fail-status-codes", "404",
        "-t", "3s",
        "-o", "json",
        "-q"
    ]

    # Calculate realistic timeout based on target count (min 300s, max 1200s)
    exec_timeout = max(300, min(1200, len(targets_for_scan) * 60))

    success, output = run_docker_tool(
        image=KITERUNNER_DOCKER_IMAGE,
        args=args,
        volume_dir=session_dir,
        timeout=exec_timeout,
        scan_id=scan_id
    )

    if is_scan_cancelled(scan_id):
        raise ScanCancelledException(f"Scan {scan_id} cancelled.")

    # Tool failure handling
    if not success:
        with open(kiterunner_stderr_file, "w", encoding="utf-8") as f:
            f.write(output or "Kiterunner execution failed.")
        with open(api_endpoints_json, "w", encoding="utf-8") as f:
            json.dump([], f, ensure_ascii=False, indent=2)
        with open(api_endpoints_file, "w", encoding="utf-8") as f:
            pass

        fail_metadata = {
            "tool": "kiterunner",
            "status": "failed",
            "input_count": len(valid_inputs),
            "raw_event_count": 0,
            "parsed_event_count": 0,
            "invalid_event_count": 0,
            "response_record_count": 0,
            "valid_count": 0,
            "invalid_response_count": 0,
            "duplicate_count": 0,
            "candidate_count": 0,
            "unique_origin_count": 0,
            "methods": {},
            "status_code_counts": {},
            "engine": "kiterunner",
            "upstream_version": KITERUNNER_UPSTREAM_VERSION,
            "upstream_commit": KITERUNNER_UPSTREAM_COMMIT,
            "build_variant": KITERUNNER_BUILD_VARIANT,
            "patches": KITERUNNER_PATCHES,
            "wordlist": os.path.basename(wordlist_param),
            "wordlist_sha256": used_wordlist_sha256
        }
        try:
            with open(kiterunner_metadata_file, "w", encoding="utf-8") as f:
                json.dump(fail_metadata, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        update_status(
            scan_id,
            progress=70,
            log_message="فشل تشغيل أداة Kiterunner أثناء فحص مسارات الـ APIs.",
            tool_status={"kiterunner": "failed"},
            stats_update={"api_endpoints_count": 0}
        )
        return False, []

    # Save untouched raw evidence
    raw_content = output or ""
    with open(kiterunner_raw_file, "w", encoding="utf-8") as f:
        f.write(raw_content)

    # Also touch kiterunner_stderr.log
    with open(kiterunner_stderr_file, "w", encoding="utf-8") as f:
        pass

    # Parse and validate raw Kiterunner evidence
    raw_lines = [l.strip() for l in raw_content.splitlines() if l.strip()]
    raw_event_count = len(raw_lines)
    parsed_event_count = 0
    invalid_event_count = 0

    response_record_count = 0
    valid_endpoints: List[Dict[str, Any]] = []
    seen_keys: Set[Tuple[str, str]] = set()
    invalid_response_count = 0
    duplicate_count = 0

    methods_count: Dict[str, int] = {}
    status_code_counts: Dict[str, int] = {}

    for line in raw_lines:
        try:
            record = json.loads(line)
        except Exception:
            invalid_event_count += 1
            continue

        if not isinstance(record, dict):
            invalid_event_count += 1
            continue

        method = record.get("method")
        if not method or not isinstance(method, str) or not method.strip():
            invalid_event_count += 1
            continue
        method = method.strip().upper()

        parsed_event_count += 1

        # Extract all responses inside the event
        responses = record.get("responses")
        candidate_resps = []
        if isinstance(responses, list) and len(responses) > 0:
            candidate_resps = responses
        else:
            fallback_uri = record.get("url")
            if not fallback_uri:
                target_base = record.get("target") or record.get("host") or ""
                path_val = record.get("path") or ""
                if target_base and path_val:
                    fallback_uri = f"{target_base.rstrip('/')}/{path_val.lstrip('/')}"

            fb_len = record.get("len")
            if fb_len is None:
                fb_len = record.get("length")
            if fb_len is None:
                fb_len = record.get("content_length")

            candidate_resps = [{
                "uri": fallback_uri,
                "sc": record.get("status_code") or record.get("sc"),
                "len": fb_len
            }]

        for resp in candidate_resps:
            response_record_count += 1

            if not isinstance(resp, dict):
                invalid_response_count += 1
                continue

            cand_url = resp.get("uri")
            status_code = resp.get("sc")
            if status_code is None:
                status_code = resp.get("status_code") or resp.get("status")

            content_length = resp.get("len")
            if content_length is None:
                content_length = resp.get("length")
            if content_length is None:
                content_length = resp.get("content_length")

            if not cand_url:
                target_base = record.get("target") or record.get("host") or ""
                path_val = record.get("path") or ""
                if target_base and path_val:
                    cand_url = f"{target_base.rstrip('/')}/{path_val.lstrip('/')}"
                elif record.get("url"):
                    cand_url = record.get("url")

            if status_code is None:
                status_code = record.get("status_code") or record.get("sc") or record.get("status")
            if content_length is None:
                content_length = record.get("len")
            if content_length is None:
                content_length = record.get("length")
            if content_length is None:
                content_length = record.get("content_length")

            if isinstance(content_length, bool) or not isinstance(content_length, int) or content_length < 0:
                content_length = None

            if not cand_url or not isinstance(cand_url, str):
                invalid_response_count += 1
                continue

            try:
                sc_int = int(status_code)
                if not (100 <= sc_int <= 599):
                    invalid_response_count += 1
                    continue
            except (ValueError, TypeError):
                invalid_response_count += 1
                continue

            norm_info = normalize_endpoint_url(cand_url)
            if not norm_info:
                invalid_response_count += 1
                continue

            norm_url, clean_path, cand_origin = norm_info

            # Provenance validation: candidate origin must match an allowed input origin
            if cand_origin not in valid_input_origins:
                invalid_response_count += 1
                continue

            # Also verify base target if present
            if record.get("target") and isinstance(record.get("target"), str):
                target_info = normalize_kiterunner_input(record.get("target"))
                if target_info and target_info[1] not in valid_input_origins:
                    invalid_response_count += 1
                    continue

            # Deduplication on canonical key (method.upper(), normalized_url)
            canon_key = (method, norm_url)
            if canon_key in seen_keys:
                duplicate_count += 1
                continue

            seen_keys.add(canon_key)

            scheme, host, port = cand_origin
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                origin_str = f"{scheme}://{host}"
            else:
                origin_str = f"{scheme}://{host}:{port}"

            endpoint_record = {
                "url": norm_url,
                "origin": origin_str,
                "method": method,
                "path": clean_path,
                "status_code": sc_int,
                "content_length": content_length,
                "source": "kiterunner"
            }
            valid_endpoints.append(endpoint_record)

            methods_count[method] = methods_count.get(method, 0) + 1
            sc_str = str(sc_int)
            status_code_counts[sc_str] = status_code_counts.get(sc_str, 0) + 1

    valid_count = len(valid_endpoints)
    candidate_count = valid_count
    unique_origin_count = len(set(ep["origin"] for ep in valid_endpoints))

    # Invariants verification
    assert raw_event_count == parsed_event_count + invalid_event_count, (
        f"Event invariant violation: raw_event={raw_event_count} != parsed={parsed_event_count} + invalid_event={invalid_event_count}"
    )
    assert response_record_count == valid_count + invalid_response_count + duplicate_count, (
        f"Response invariant violation: responses={response_record_count} != valid={valid_count} + invalid_resp={invalid_response_count} + dup={duplicate_count}"
    )

    # Prioritize primary entered target at top of output lists without fabricating new URLs
    stat = get_status(scan_id) or {}
    dom = stat.get("target_domain", "")
    valid_endpoints = prioritize_dict_records(valid_endpoints, dom, key="url")

    # Save discovered API endpoints
    with open(api_endpoints_json, "w", encoding="utf-8") as f:
        json.dump(valid_endpoints, f, ensure_ascii=False, indent=2)

    with open(api_endpoints_file, "w", encoding="utf-8") as f:
        for ep in valid_endpoints:
            f.write(f"{ep['url']}\n")

    # Save metadata
    metadata = {
        "tool": "kiterunner",
        "status": "completed",
        "input_count": len(valid_inputs),
        "raw_event_count": raw_event_count,
        "parsed_event_count": parsed_event_count,
        "invalid_event_count": invalid_event_count,
        "response_record_count": response_record_count,
        "valid_count": valid_count,
        "invalid_response_count": invalid_response_count,
        "duplicate_count": duplicate_count,
        "candidate_count": candidate_count,
        "unique_origin_count": unique_origin_count,
        "methods": methods_count,
        "status_code_counts": status_code_counts,
        "engine": "kiterunner",
        "upstream_version": KITERUNNER_UPSTREAM_VERSION,
        "upstream_commit": KITERUNNER_UPSTREAM_COMMIT,
        "build_variant": KITERUNNER_BUILD_VARIANT,
        "patches": KITERUNNER_PATCHES,
        "wordlist": os.path.basename(wordlist_param),
        "wordlist_sha256": used_wordlist_sha256
    }
    try:
        with open(kiterunner_metadata_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    # Print discovered route candidates directly to stdout
    for ep in valid_endpoints:
        print(f"{ep['method']} {ep['url']} [{ep['status_code']}]", flush=True)
    if valid_endpoints:
        print("", flush=True)

    if candidate_count > 0:
        log_msg = f"اكتمل استكشاف مسارات الـ APIs: تم اكتشاف {candidate_count} مسار API مرشح (API Route Candidates) بواسطة Kiterunner."
        tool_status = "success"
    else:
        log_msg = "اكتمل استكشاف مسارات الـ APIs: لم يتم العثور على أي مسار API بواسطة Kiterunner (0 مسارات)."
        tool_status = "empty"

    update_status(
        scan_id,
        progress=70,
        log_message=log_msg,
        tool_status={"kiterunner": tool_status},
        stats_update={"api_endpoints_count": candidate_count}
    )

    return True, valid_endpoints
