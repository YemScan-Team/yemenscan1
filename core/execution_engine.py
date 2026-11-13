import os
import json
import time
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from core.session import get_session_dir, get_status, update_status, SCANS_DIR
from core.runner import is_docker_available, run_docker_tool, run_local_tool
from core.stage1_discovery import run_subfinder, run_naabu
from core.stage2_web_probing import run_httpx, run_kiterunner_or_api_probing
from core.stage3_vulnerabilities import (
    prepare_nuclei_targets,
    run_nuclei,
    run_wapiti_dast,
    unify_and_save_vulnerabilities,
    NUCLEI_DOCKER_IMAGE,
    WAPITI_DOCKER_IMAGE
)
from database import SessionLocal
from core.db_service import ingest_scan_from_directory, complete_scan_session

STANDALONE_DIR = os.path.join(SCANS_DIR, "_standalone")
os.makedirs(STANDALONE_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# 1. Pipeline Stages Execution (المراحل الثلاث لخط الفحص)
# ---------------------------------------------------------------------------

def run_stage1_pipeline(scan_id: str, domain: Optional[str] = None) -> Dict[str, Any]:
    """
    Executes Stage 1 (Discovery & Port Scanning): Subfinder -> Naabu.
    Reads/writes from session directory and ingests findings to Database.
    """
    session_dir = get_session_dir(scan_id)
    stat = get_status(scan_id) or {}
    target_domain = domain or stat.get("target_domain")
    if not target_domain:
        raise ValueError(f"Target domain for scan_id '{scan_id}' not found.")

    update_status(
        scan_id,
        status="running",
        stage="phase1_discovery",
        progress=10,
        log_message=f"تشغيل المرحلة الأولى (Subfinder + Naabu) للنطاق: {target_domain}"
    )

    # 1. Subfinder
    ok_sub, subdomains = run_subfinder(target_domain, session_dir, scan_id)

    # 2. Naabu
    clean_domain = target_domain.strip().lower()
    if "://" in clean_domain:
        clean_domain = clean_domain.split("://", 1)[1]
    clean_domain = clean_domain.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    naabu_targets = [clean_domain] + [s for s in subdomains if s.lower() != clean_domain]

    ok_ports, open_ports = run_naabu(naabu_targets, session_dir, scan_id)

    # Ingest to DB
    try:
        with SessionLocal() as db:
            ingest_scan_from_directory(db, scan_id, domain=target_domain)
    except Exception as e:
        print(f"[!] Warning: DB ingestion error after stage 1: {e}", flush=True)

    update_status(
        scan_id,
        status="running",
        stage="phase1_completed",
        progress=35,
        log_message=f"اكتملت المرحلة الأولى: {len(subdomains)} نطاق فرعي، و {len(open_ports)} منفذ مفتوح."
    )

    return {
        "status": "success",
        "scan_id": scan_id,
        "stage": "stage1_discovery",
        "target_domain": target_domain,
        "subdomains_count": len(subdomains),
        "subdomains": subdomains,
        "open_ports_count": len(open_ports),
        "open_ports": open_ports
    }


def run_stage2_pipeline(scan_id: str) -> Dict[str, Any]:
    """
    Executes Stage 2 (Web & API Probing): HTTPX -> Kiterunner.
    Uses discovered ports/hosts from session directory.
    """
    session_dir = get_session_dir(scan_id)
    stat = get_status(scan_id) or {}
    target_domain = stat.get("target_domain", "unknown")

    update_status(
        scan_id,
        status="running",
        stage="phase2_web_probing",
        progress=40,
        log_message="تشغيل المرحلة الثانية (HTTPX + Kiterunner) لفحص خدمات الويب وواجهات برمجة التطبيقات..."
    )

    # 1. HTTPX
    ok_http, web_targets, active_urls = run_httpx(session_dir, scan_id)

    # 2. Kiterunner
    api_endpoints = []
    if active_urls:
        ok_api, api_endpoints = run_kiterunner_or_api_probing(active_urls, session_dir, scan_id)

    # Ingest to DB
    try:
        with SessionLocal() as db:
            ingest_scan_from_directory(db, scan_id, domain=target_domain)
    except Exception as e:
        print(f"[!] Warning: DB ingestion error after stage 2: {e}", flush=True)

    update_status(
        scan_id,
        status="running",
        stage="phase2_completed",
        progress=65,
        log_message=f"اكتملت المرحلة الثانية: {len(active_urls)} خدمة ويب نشطة، و {len(api_endpoints)} مسار API."
    )

    return {
        "status": "success",
        "scan_id": scan_id,
        "stage": "stage2_web_probing",
        "active_urls_count": len(active_urls),
        "active_urls": active_urls,
        "api_endpoints_count": len(api_endpoints),
        "api_endpoints": api_endpoints
    }


def run_stage3_pipeline(scan_id: str) -> Dict[str, Any]:
    """
    Executes Stage 3 (Vulnerability Assessment): Nuclei (CVE/OWASP) + Wapiti (DAST).
    Unifies findings and updates database.
    """
    session_dir = get_session_dir(scan_id)
    stat = get_status(scan_id) or {}
    target_domain = stat.get("target_domain", "unknown")

    update_status(
        scan_id,
        status="running",
        stage="phase3_vulnerabilities",
        progress=70,
        log_message="تشغيل المرحلة الثالثة (Nuclei + Wapiti) لفحص الثغرات الأمنية..."
    )

    all_targets = prepare_nuclei_targets(session_dir)

    # 1. Nuclei
    nuclei_findings = []
    if all_targets:
        ok_nuc, nuclei_findings = run_nuclei(session_dir, scan_id)

    # 2. Wapiti
    active_urls = []
    active_urls_file = os.path.join(session_dir, "active_urls.txt")
    if os.path.exists(active_urls_file):
        with open(active_urls_file, "r", encoding="utf-8") as f:
            active_urls = [line.strip() for line in f if line.strip()]

    wapiti_findings = []
    if active_urls:
        ok_wap, wapiti_findings = run_wapiti_dast(session_dir, scan_id, active_urls)

    # 3. Unify Findings
    unify_and_save_vulnerabilities(session_dir, scan_id, nuclei_findings, wapiti_findings)

    # Ingest to DB
    try:
        with SessionLocal() as db:
            ingest_scan_from_directory(db, scan_id, domain=target_domain)
            complete_scan_session(db, scan_id, status="completed")
    except Exception as e:
        print(f"[!] Warning: DB ingestion error after stage 3: {e}", flush=True)

    update_status(
        scan_id,
        status="completed",
        stage="completed",
        progress=100,
        is_completed=True,
        log_message=f"اكتملت المرحلة الثالثة: اكتشاف {len(nuclei_findings)} ثغرة عبر Nuclei و {len(wapiti_findings)} ثغرة عبر Wapiti."
    )

    return {
        "status": "success",
        "scan_id": scan_id,
        "stage": "stage3_vulnerabilities",
        "nuclei_findings_count": len(nuclei_findings),
        "wapiti_findings_count": len(wapiti_findings),
        "total_vulnerabilities": len(nuclei_findings) + len(wapiti_findings)
    }


# ---------------------------------------------------------------------------
# 2. Pipeline In-Session Tool Execution (تشغيل أداة محددة داخل جلسة الفحص)
# ---------------------------------------------------------------------------

def run_tool_in_session(scan_id: str, tool_name: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Runs a single tool inside an active or existing scan session directory.
    Tool choices: 'subfinder', 'naabu', 'httpx', 'kiterunner', 'nuclei', 'wapiti'.
    """
    tool_lower = tool_name.strip().lower()
    session_dir = get_session_dir(scan_id)
    stat = get_status(scan_id) or {}
    domain = stat.get("target_domain")

    if not os.path.exists(session_dir):
        raise FileNotFoundError(f"Session directory for scan_id '{scan_id}' not found.")

    options = options or {}

    if tool_lower == "subfinder":
        if not domain:
            raise ValueError("Target domain is required for subfinder.")
        ok, subdomains = run_subfinder(domain, session_dir, scan_id)
        return {"tool": "subfinder", "status": "success" if ok else "failed", "subdomains": subdomains, "count": len(subdomains)}

    elif tool_lower == "naabu":
        targets = options.get("targets")
        if not targets:
            sub_file = os.path.join(session_dir, "subdomains.txt")
            if os.path.exists(sub_file):
                with open(sub_file, "r", encoding="utf-8") as f:
                    targets = [line.strip() for line in f if line.strip()]
            if not targets and domain:
                targets = [domain]
        ok, open_ports = run_naabu(targets or [domain], session_dir, scan_id)
        return {"tool": "naabu", "status": "success" if ok else "failed", "open_ports": open_ports, "count": len(open_ports)}

    elif tool_lower == "httpx":
        ok, web_targets, active_urls = run_httpx(session_dir, scan_id)
        return {"tool": "httpx", "status": "success" if ok else "failed", "active_urls": active_urls, "count": len(active_urls)}

    elif tool_lower == "kiterunner":
        active_urls = options.get("urls")
        if not active_urls:
            urls_file = os.path.join(session_dir, "active_urls.txt")
            if os.path.exists(urls_file):
                with open(urls_file, "r", encoding="utf-8") as f:
                    active_urls = [line.strip() for line in f if line.strip()]
        if not active_urls:
            return {"tool": "kiterunner", "status": "skipped", "message": "No active URLs found to probe APIs.", "count": 0}
        ok, api_endpoints = run_kiterunner_or_api_probing(active_urls, session_dir, scan_id)
        return {"tool": "kiterunner", "status": "success" if ok else "failed", "api_endpoints": api_endpoints, "count": len(api_endpoints)}

    elif tool_lower == "nuclei":
        prepare_nuclei_targets(session_dir)
        ok, findings = run_nuclei(session_dir, scan_id)
        return {"tool": "nuclei", "status": "success" if ok else "failed", "findings": findings, "count": len(findings)}

    elif tool_lower == "wapiti":
        active_urls = options.get("urls")
        if not active_urls:
            urls_file = os.path.join(session_dir, "active_urls.txt")
            if os.path.exists(urls_file):
                with open(urls_file, "r", encoding="utf-8") as f:
                    active_urls = [line.strip() for line in f if line.strip()]
        if not active_urls:
            return {"tool": "wapiti", "status": "skipped", "message": "No active URLs found for Wapiti DAST.", "count": 0}
        ok, findings = run_wapiti_dast(session_dir, scan_id, active_urls)
        return {"tool": "wapiti", "status": "success" if ok else "failed", "findings": findings, "count": len(findings)}

    else:
        raise ValueError(f"Unknown tool name: {tool_name}. Choose from: subfinder, naabu, httpx, kiterunner, nuclei, wapiti")


# ---------------------------------------------------------------------------
# 3. Independent Standalone Tool Execution (الفحص المستقل للأدوات)
# ---------------------------------------------------------------------------

def run_standalone_subfinder(domain: str) -> Dict[str, Any]:
    """Runs Subfinder independently on a domain, returning discovered subdomains."""
    run_id = f"subfinder_{uuid.uuid4().hex[:8]}"
    work_dir = os.path.join(STANDALONE_DIR, run_id)
    os.makedirs(work_dir, exist_ok=True)
    ok, subdomains = run_subfinder(domain, work_dir, run_id)
    return {
        "tool": "subfinder",
        "status": "success" if ok else "failed",
        "target_domain": domain,
        "subdomains_count": len(subdomains),
        "subdomains": subdomains
    }


def run_standalone_naabu(target: str, ports: Optional[str] = None) -> Dict[str, Any]:
    """Runs Naabu independently on a host or IP, returning open ports."""
    run_id = f"naabu_{uuid.uuid4().hex[:8]}"
    work_dir = os.path.join(STANDALONE_DIR, run_id)
    os.makedirs(work_dir, exist_ok=True)

    clean_target = target.strip()
    ok, open_ports = run_naabu([clean_target], work_dir, run_id)
    return {
        "tool": "naabu",
        "status": "success" if ok else "failed",
        "target": clean_target,
        "open_ports_count": len(open_ports),
        "open_ports": open_ports
    }


def run_standalone_httpx(targets: List[str]) -> Dict[str, Any]:
    """Runs HTTPX independently on a list of URLs or hosts."""
    run_id = f"httpx_{uuid.uuid4().hex[:8]}"
    work_dir = os.path.join(STANDALONE_DIR, run_id)
    os.makedirs(work_dir, exist_ok=True)

    # Write input targets to ports.txt and httpx_input.txt
    ports_file = os.path.join(work_dir, "ports.txt")
    with open(ports_file, "w", encoding="utf-8") as f:
        for t in targets:
            clean = t.strip()
            if clean:
                if ":" not in clean and not clean.startswith("http"):
                    f.write(f"{clean}:80\n{clean}:443\n")
                else:
                    f.write(f"{clean}\n")

    ok, web_targets, active_urls = run_httpx(work_dir, run_id)
    return {
        "tool": "httpx",
        "status": "success" if ok else "failed",
        "total_active_urls": len(active_urls),
        "active_urls": active_urls,
        "web_targets": web_targets
    }


def run_standalone_kiterunner(target_url: str) -> Dict[str, Any]:
    """Runs Kiterunner independently to discover API routes."""
    run_id = f"kiterunner_{uuid.uuid4().hex[:8]}"
    work_dir = os.path.join(STANDALONE_DIR, run_id)
    os.makedirs(work_dir, exist_ok=True)

    ok, api_endpoints = run_kiterunner_or_api_probing([target_url.strip()], work_dir, run_id)
    return {
        "tool": "kiterunner",
        "status": "success" if ok else "failed",
        "target_url": target_url.strip(),
        "total_api_endpoints": len(api_endpoints),
        "api_endpoints": api_endpoints
    }


def run_standalone_nuclei(target_url: str, severity: Optional[str] = None) -> Dict[str, Any]:
    """Runs Nuclei independently against a target URL."""
    run_id = f"nuclei_{uuid.uuid4().hex[:8]}"
    work_dir = os.path.join(STANDALONE_DIR, run_id)
    os.makedirs(work_dir, exist_ok=True)

    targets_file = os.path.join(work_dir, "active_urls.txt")
    with open(targets_file, "w", encoding="utf-8") as f:
        f.write(f"{target_url.strip()}\n")

    prepare_nuclei_targets(work_dir)
    ok, findings = run_nuclei(work_dir, run_id)
    return {
        "tool": "nuclei",
        "status": "success" if ok else "failed",
        "target_url": target_url.strip(),
        "total_findings": len(findings),
        "findings": findings
    }


def run_standalone_wapiti(target_url: str, modules: Optional[str] = None) -> Dict[str, Any]:
    """Runs Wapiti DAST independently against a target URL."""
    run_id = f"wapiti_{uuid.uuid4().hex[:8]}"
    work_dir = os.path.join(STANDALONE_DIR, run_id)
    os.makedirs(work_dir, exist_ok=True)

    ok, findings = run_wapiti_dast(work_dir, run_id, [target_url.strip()])
    return {
        "tool": "wapiti",
        "status": "success" if ok else "failed",
        "target_url": target_url.strip(),
        "total_findings": len(findings),
        "findings": findings
    }


# ---------------------------------------------------------------------------
# 4. Tools Health & Readiness Check (فحص جاهزية وحالة الحاويات الست)
# ---------------------------------------------------------------------------

def get_tools_readiness_status() -> Dict[str, Any]:
    """
    Checks Docker availability and verified readiness of all 6 security tools:
    Subfinder, Naabu, HTTPX, Kiterunner, Nuclei, Wapiti.
    """
    docker_ready = is_docker_available()
    tools = {
        "subfinder": {
            "name": "ProjectDiscovery Subfinder",
            "type": "Passive Subdomain Enumeration",
            "docker_image": "projectdiscovery/subfinder:v2.17.0",
            "ready": docker_ready
        },
        "naabu": {
            "name": "ProjectDiscovery Naabu",
            "type": "High-Speed Port Scanner",
            "docker_image": "projectdiscovery/naabu:v2.6.1",
            "ready": docker_ready
        },
        "httpx": {
            "name": "ProjectDiscovery HTTPX",
            "type": "Web Service & Tech Stack Probing",
            "docker_image": "projectdiscovery/httpx:v1.12.0",
            "ready": docker_ready
        },
        "kiterunner": {
            "name": "Assetnote Kiterunner",
            "type": "Content-Aware API Route Discovery",
            "docker_image": "yemscan/kiterunner:v1.0.2-yemscan1",
            "ready": docker_ready
        },
        "nuclei": {
            "name": "ProjectDiscovery Nuclei",
            "type": "Vulnerability Scanner (CVEs & OWASP)",
            "docker_image": NUCLEI_DOCKER_IMAGE,
            "ready": docker_ready
        },
        "wapiti": {
            "name": "Wapiti DAST Scanner",
            "type": "Dynamic Application Security Testing",
            "docker_image": WAPITI_DOCKER_IMAGE,
            "ready": docker_ready
        }
    }

    return {
        "status": "healthy" if docker_ready else "degraded",
        "docker_available": docker_ready,
        "tools_count": len(tools),
        "tools": tools,
        "engine": "Docker Engine (yemenscan_prod)" if docker_ready else "Host Process Fallback"
    }
