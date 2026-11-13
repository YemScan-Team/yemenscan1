import os
import json
import re
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse
from fastapi import FastAPI, BackgroundTasks, HTTPException, Query, Depends
from fastapi.responses import HTMLResponse, FileResponse, Response, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db, SessionLocal, Base, engine
from models import (
    Targets,
    ScanSessions,
    Assets,
    VulnerabilityCatalog,
    VulnerabilityFindings,
    AIReports,
)
from core.db_service import (
    create_target_and_session,
    save_discovered_assets,
    ingest_vulnerabilities,
    complete_scan_session,
    save_ai_report,
    ingest_scan_from_directory,
)
from core.session import (
    create_scan_session,
    get_status,
    get_session_dir,
    list_all_scans
)
from core.pipeline import run_full_pipeline
from core.target_validator import validate_target_domain, TargetValidationError
from core.target_prioritizer import prioritize_hosts, prioritize_ports, prioritize_urls, prioritize_dict_records

from datetime import datetime

# Safe environment loading for Google Gemini API
def get_gemini_api_key() -> Optional[str]:
    """Dynamically and securely fetches GEMINI_API_KEY from environment or .env file."""
    try:
        from dotenv import load_dotenv
        load_dotenv(override=True)
    except Exception:
        pass
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
        if os.path.exists(env_file):
            try:
                with open(env_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("GEMINI_API_KEY=") and not line.startswith("#"):
                            k = line.split("=", 1)[1].strip().strip('"').strip("'")
                            if k:
                                key = k
                                os.environ["GEMINI_API_KEY"] = k
                                break
            except Exception:
                pass
    return key

GEMINI_API_KEY = get_gemini_api_key()

try:
    import warnings
    warnings.filterwarnings("ignore", category=FutureWarning)
    import google.generativeai as genai
    if GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
except ImportError:
    genai = None

app = FastAPI(
    title="YemenScan - منظومة الفحص الأمني السحابي",
    description="منصة آلية لإدارة سطح الهجوم وفحص واجهات برمجة التطبيقات وثغرات الويب وفق معايير OWASP و CVE",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class ScanRequest(BaseModel):
    domain: Optional[str] = None
    target: Optional[str] = None

class NucleiScanRequest(BaseModel):
    target: str
    category: Optional[str] = None

def sanitize_domain(v: str, check_dns: bool = True) -> str:
    """
    Sanitizes and validates a domain name using strict RFC syntax,
    valid TLD, and active DNS resolution checks.
    """
    try:
        clean, _ = validate_target_domain(v, check_dns=check_dns)
        return clean
    except TargetValidationError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)

@app.get("/", include_in_schema=False)
def root():
    """Redirects root URL directly to the interactive Swagger API documentation."""
    return RedirectResponse(url="/docs")

@app.on_event("startup")
def on_startup():
    """Ensure database tables exist on startup."""
    try:
        Base.metadata.create_all(bind=engine)
        print("[*] Database tables verified/created successfully.", flush=True)
    except Exception as e:
        print(f"[!] Warning: Database connection error on startup: {e}", flush=True)


def run_scan_pipeline_and_ingest(domain: str, scan_id: str):
    """
    Executes the full scanning pipeline and persists discovered
    assets, vulnerabilities, and status updates into the database.
    """
    try:
        run_full_pipeline(domain, scan_id)
        try:
            with SessionLocal() as db:
                ingest_scan_from_directory(db, scan_id, domain=domain)
        except Exception as db_err:
            print(f"[!] Database ingestion error for {scan_id}: {db_err}", flush=True)
    except Exception as e:
        print(f"[!] Error in scan background task for {scan_id}: {e}", flush=True)
        try:
            with SessionLocal() as db:
                complete_scan_session(db, scan_id, status="failed")
        except Exception:
            pass


class TargetValidationRequest(BaseModel):
    domain: Optional[str] = None
    target: Optional[str] = None


@app.post("/api/target/validate")
@app.get("/api/target/validate")
def validate_target_endpoint(
    domain: Optional[str] = Query(None),
    target: Optional[str] = Query(None),
    request: Optional[TargetValidationRequest] = None
):
    """
    Pre-flight validation endpoint to verify domain syntax, public TLD,
    and active DNS resolution (A/AAAA records) BEFORE initiating a scan.
    """
    raw_target = None
    if isinstance(domain, str) and domain.strip():
        raw_target = domain.strip()
    elif isinstance(target, str) and target.strip():
        raw_target = target.strip()
    elif request:
        if isinstance(request.domain, str) and request.domain.strip():
            raw_target = request.domain.strip()
        elif isinstance(request.target, str) and request.target.strip():
            raw_target = request.target.strip()

    if not raw_target:
        raise HTTPException(
            status_code=400,
            detail="يرجى إدخال اسم النطاق أو الرابط المستهدف للتحقق منه."
        )

    try:
        clean_domain, resolved_ips = validate_target_domain(raw_target, check_dns=True)
        return {
            "status": "valid",
            "valid": True,
            "target_raw": raw_target,
            "clean_domain": clean_domain,
            "resolved_ips": resolved_ips,
            "primary_ip": resolved_ips[0] if resolved_ips else None,
            "message": f"النطاق '{clean_domain}' صالح ونشط على شبكة الإنترنت ويمتلك سجلات DNS موثوقة ({len(resolved_ips)} IP).",
            "ready_to_scan": True
        }
    except TargetValidationError as ve:
        return {
            "status": "invalid",
            "valid": False,
            "target_raw": raw_target,
            "error": ve.message,
            "error_code": ve.code,
            "ready_to_scan": False
        }
    except Exception as exc:
        return {
            "status": "invalid",
            "valid": False,
            "target_raw": raw_target,
            "error": f"خطأ أثناء فحص النطاق عبر خوادم DNS: {str(exc)}",
            "error_code": "DNS_ERROR",
            "ready_to_scan": False
        }


@app.post("/api/scan/start")
def start_scan(
    background_tasks: BackgroundTasks,
    domain: Optional[str] = Query(None),
    request: Optional[ScanRequest] = None,
    db: Session = Depends(get_db)
):
    """
    Starts an end-to-end security assessment across Phase 1, Phase 2, and Phase 3.
    Accepts target domain via query parameter ?domain=... OR JSON body {"domain": "..."}.
    Enforces strict RFC syntax, public TLD validation, and active DNS resolution before starting.
    """
    target_raw = None
    if isinstance(domain, str) and domain.strip():
        target_raw = domain.strip()
    elif request:
        if isinstance(request.domain, str) and request.domain.strip():
            target_raw = request.domain.strip()
        elif isinstance(request.target, str) and request.target.strip():
            target_raw = request.target.strip()
        
    if not target_raw:
        raise HTTPException(
            status_code=400,
            detail="يرجى تحديد النطاق المستهدف عبر query parameter ?domain=... أو داخل الـ JSON body."
        )

    # 1. Strict Target Validation (Syntax, TLD, and Live DNS Resolution)
    try:
        clean_domain, resolved_ips = validate_target_domain(target_raw, check_dns=True)
    except TargetValidationError as ve:
        raise HTTPException(status_code=ve.status_code, detail=ve.message)

    # 2. Initialize Scan Session & Database Tracking
    scan_id = create_scan_session(clean_domain)

    try:
        create_target_and_session(db, clean_domain, scan_id)
    except Exception as e:
        print(f"[!] Warning: Could not register scan session in DB: {e}", flush=True)

    print(f"\n[*] تم التحقق بنجاح من النطاق ({clean_domain} -> {resolved_ips}). تشغيل أدوات الفحص في الخلفية...", flush=True)
    
    # 3. Pass to background execution
    background_tasks.add_task(run_scan_pipeline_and_ingest, clean_domain, scan_id)
    
    return {
        "status": "success",
        "scan_id": scan_id,
        "target_domain": clean_domain,
        "resolved_ips": resolved_ips,
        "message": f"تم التحقق بنجاح من النطاق '{clean_domain}'. بدأت منظومة الفحص الأمني العمل في الخلفية.",
        "phases": [
            "المرحلة الأولى: Subfinder (النطاقات) + Naabu (المنافذ)",
            "المرحلة الثانية: HTTPX (الخدمات الحية) + Kiterunner (واجهات الـ APIs)",
            "المرحلة الثالثة: Nuclei (CVEs و OWASP API) + Wapiti (DAST)"
        ]
    }

@app.post("/api/scan/{scan_id}/stop")
@app.post("/api/scan/stop")
def stop_scan_endpoint(scan_id: Optional[str] = None, db: Session = Depends(get_db)):
    """
    إيقاف عملية الفحص الجارية فوراً وإنهاء كافة العمليات والأدوات والحاويات التابعة لها.
    """
    if not scan_id:
        all_scans = list_all_scans()
        if all_scans:
            # Prefer stopping an actively running scan
            running_scans = [s for s in all_scans if not s.get("is_completed") and s.get("current_stage") != "stopped"]
            if running_scans:
                scan_id = running_scans[0]["scan_id"]
            else:
                scan_id = all_scans[0]["scan_id"]
        else:
            raise HTTPException(status_code=404, detail="لا توجد عمليات فحص مسجلة.")

    status = get_status(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail="جلسة الفحص غير موجودة.")

    from core.session import stop_scan_session
    stop_scan_session(scan_id)

    try:
        complete_scan_session(db, scan_id, status="stopped")
    except Exception as e:
        print(f"[!] Warning: failed to mark session stopped in DB: {e}", flush=True)

    return {
        "status": "success",
        "scan_id": scan_id,
        "message": f"تم إيقاف عملية الفحص '{scan_id}' بنجاح."
    }

@app.get("/api/scans")
def get_all_scans(db: Session = Depends(get_db)):
    """Returns a list of all historical scan sessions from database."""
    scans_list = []
    try:
        db_sessions = (
            db.query(ScanSessions)
            .join(Targets, ScanSessions.target_id == Targets.id)
            .order_by(ScanSessions.started_at.desc())
            .all()
        )
        for s in db_sessions:
            status_file_info = get_status(s.scan_id) or {}
            is_completed = (
                s.status in ("completed", "failed", "stopped")
                or status_file_info.get("is_completed", False)
            )
            current_stage = status_file_info.get("current_stage") or s.status
            progress = status_file_info.get(
                "progress_percentage", 100 if s.status == "completed" else (0 if s.status == "pending" else 50)
            )

            stats = status_file_info.get("stats")
            if not stats or not stats.get("vulnerabilities_count"):
                vuln_by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                for f in s.findings:
                    sev = (f.severity or "info").lower()
                    if sev in vuln_by_sev:
                        vuln_by_sev[sev] += 1

                subdomains = {urlparse(a.url).netloc.split(":")[0] for a in s.assets if a.url}
                ports = set()
                for a in s.assets:
                    if a.open_ports:
                        for p in str(a.open_ports).split(","):
                            if p.strip():
                                ports.add(p.strip())
                live_urls = [a for a in s.assets if not a.is_api]
                api_eps = [a for a in s.assets if a.is_api]

                stats = {
                    "subdomains_count": len(subdomains),
                    "open_ports_count": len(ports),
                    "live_urls_count": len(live_urls),
                    "api_endpoints_count": len(api_eps),
                    "vulnerabilities_count": len(s.findings),
                    "vuln_by_severity": vuln_by_sev,
                }

            scans_list.append({
                "scan_id": s.scan_id,
                "target_domain": s.target.domain_name if s.target else "unknown",
                "created_at": s.started_at.isoformat() if s.started_at else status_file_info.get("created_at", ""),
                "status": s.status or status_file_info.get("status") or current_stage,
                "current_stage": current_stage,
                "progress": progress,
                "is_completed": is_completed,
                "has_error": status_file_info.get("has_error", s.status in ("failed", "partial")),
                "stats": stats,
            })
    except Exception as e:
        print(f"[!] Warning: failed to retrieve scans from DB: {e}", flush=True)

    # Merge any scans on disk not yet in the DB
    disk_scans = list_all_scans()
    existing_ids = {s["scan_id"] for s in scans_list}
    for ds in disk_scans:
        if ds["scan_id"] not in existing_ids:
            scans_list.append(ds)

    return {
        "status": "success",
        "scans": scans_list
    }

@app.get("/api/scan/status")
@app.get("/api/scan/{scan_id}/status")
def get_scan_status(scan_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Retrieves real-time execution progress, current tool, and metrics."""
    if not scan_id:
        try:
            latest_session = db.query(ScanSessions).order_by(ScanSessions.started_at.desc()).first()
            if latest_session:
                scan_id = latest_session.scan_id
        except Exception:
            pass

        if not scan_id:
            all_scans = list_all_scans()
            if all_scans:
                scan_id = all_scans[0]["scan_id"]
            else:
                raise HTTPException(status_code=404, detail="لا توجد عمليات فحص مسجلة حتى الآن.")
            
    status = get_status(scan_id)
    if not status:
        try:
            db_session = db.query(ScanSessions).filter(ScanSessions.scan_id == scan_id).first()
            if db_session:
                stats = db_session.stats_summary
                if not stats:
                    subdomains = {urlparse(a.url).netloc.split(":")[0] for a in db_session.assets if a.url}
                    stats = {
                        "subdomains_count": len(subdomains),
                        "live_urls_count": len([a for a in db_session.assets if not a.is_api]),
                        "api_endpoints_count": len([a for a in db_session.assets if a.is_api]),
                        "vulnerabilities_count": len(db_session.findings),
                    }
                status = {
                    "scan_id": db_session.scan_id,
                    "target_domain": db_session.target.domain_name if db_session.target else "unknown",
                    "current_stage": db_session.current_stage or db_session.status,
                    "progress_percentage": db_session.progress,
                    "is_completed": db_session.status in ("completed", "failed", "stopped"),
                    "status": db_session.status,
                    "stats": stats,
                    "created_at": db_session.started_at.isoformat() if db_session.started_at else "",
                    "logs": db_session.execution_logs or [],
                }
        except Exception as e:
            print(f"[!] Warning: DB status query error: {e}", flush=True)

    if not status:
        raise HTTPException(status_code=404, detail="جلسة الفحص غير موجودة.")
    return {
        "status": "success",
        "data": status
    }

@app.get("/api/scan/results")
@app.get("/api/scan/{scan_id}/results")
def get_scan_results(scan_id: Optional[str] = None):
    """
    Returns live web URLs (HTTPX) isolated strictly by scan session.
    If scan_id is omitted, returns results from the latest scan session.
    """
    file_path = None
    active_scan_id = scan_id
    
    if scan_id:
        session_dir = get_session_dir(scan_id)
        cand = os.path.join(session_dir, "active_urls.json")
        if os.path.exists(cand):
            file_path = cand
    else:
        all_scans = list_all_scans()
        if all_scans:
            active_scan_id = all_scans[0]["scan_id"]
            cand = os.path.join(get_session_dir(active_scan_id), "active_urls.json")
            if os.path.exists(cand):
                file_path = cand
                
    if not file_path or not os.path.exists(file_path):
        return {
            "status": "success",
            "scan_id": active_scan_id,
            "total_urls_found": 0,
            "data": []
        }
    
    try:
        results = []
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            for line in file:
                if line.strip():
                    try:
                        results.append(json.loads(line.strip()))
                    except Exception:
                        pass
                        
        stat = get_status(active_scan_id) if active_scan_id else {}
        target_domain = (stat or {}).get("target_domain", "")
        results = prioritize_dict_records(results, target_domain, key="url")

        return {
            "status": "success",
            "scan_id": active_scan_id,
            "total_urls_found": len(results),
            "data": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"خطأ أثناء قراءة النتائج: {str(e)}")

@app.get("/api/scan/vulnerabilities")
@app.get("/api/scan/{scan_id}/vulnerabilities")
def get_vulnerabilities(scan_id: Optional[str] = None, db: Session = Depends(get_db)):
    """
    Unified Vulnerability Findings (Nuclei + Wapiti) queried from VulnerabilityFindings
    joined with VulnerabilityCatalog, including CVE, CWE, CVSS, and OWASP metadata.
    """
    active_scan_id = scan_id
    if not active_scan_id:
        try:
            latest = db.query(ScanSessions).order_by(ScanSessions.started_at.desc()).first()
            if latest:
                active_scan_id = latest.scan_id
        except Exception:
            pass

        if not active_scan_id:
            all_scans = list_all_scans()
            if all_scans:
                active_scan_id = all_scans[0]["scan_id"]

    if not active_scan_id:
        return {
            "status": "success",
            "scan_id": None,
            "total_vulnerabilities_found": 0,
            "vulnerabilities": [],
            "data": []
        }

    results = []
    try:
        rows = (
            db.query(VulnerabilityFindings, VulnerabilityCatalog)
            .outerjoin(VulnerabilityCatalog, VulnerabilityFindings.catalog_id == VulnerabilityCatalog.id)
            .filter(VulnerabilityFindings.scan_id == active_scan_id)
            .all()
        )
        if rows:
            for finding, catalog in rows:
                raw = finding.raw_output or {}
                cve_id = (catalog.cve_id if catalog else None) or raw.get("cve_id")
                cwe_id = (catalog.cwe_id if catalog else None) or raw.get("cwe_id")
                cvss_score = (catalog.cvss_score if catalog else None) or raw.get("cvss_score")
                cvss_vector = (catalog.cvss_vector if catalog else None) or raw.get("cvss_vector")
                owasp_cat = (catalog.owasp_category if catalog else None) or raw.get("category", "General")
                title = (catalog.title if catalog else None) or raw.get("title", "Unknown Vulnerability")
                desc = (catalog.description if catalog else None) or raw.get("description", "")
                remediation = (catalog.standard_remediation if catalog else None) or raw.get("remediation", "")

                # Dynamic fallback enrichment from normalizer if cvss_score is missing
                if cvss_score is None:
                    from core.vuln_normalizer import normalize_vulnerability
                    norm = normalize_vulnerability({
                        "title": title,
                        "cwe": cwe_id or raw.get("cwe"),
                        "cve": cve_id or raw.get("cve"),
                        "severity": finding.severity,
                        "info": raw.get("info", {})
                    })
                    cvss_score = norm.get("cvss_score")
                    if not cvss_vector:
                        cvss_vector = norm.get("cvss_vector")
                    if not cwe_id:
                        cwe_id = norm.get("cwe_id")
                    if not owasp_cat or owasp_cat == "General":
                        owasp_cat = norm.get("owasp_category") or owasp_cat
                    if not remediation:
                        remediation = norm.get("standard_remediation") or remediation

                results.append({
                    "id": cve_id or raw.get("id") or f"VULN-{finding.id}",
                    "title": title,
                    "severity": (finding.severity or "info").upper(),
                    "source": raw.get("source", "Vulnerability Engine"),
                    "category": owasp_cat,
                    "url": finding.affected_url,
                    "description": desc,
                    "remediation": remediation,
                    "evidence": finding.evidence,
                    "cve_id": cve_id,
                    "cwe_id": cwe_id,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "owasp_category": owasp_cat,
                    "discovered_at": finding.discovered_at.isoformat() if finding.discovered_at else None,
                    "raw_output": raw
                })
    except Exception as e:
        print(f"[!] Warning: DB query failed for vulnerabilities: {e}", flush=True)

    if not results:
        session_dir = get_session_dir(active_scan_id)
        file_path = None
        cand = os.path.join(session_dir, "unified_vulnerabilities.json")
        if os.path.exists(cand):
            file_path = cand
        else:
            cand2 = os.path.join(session_dir, "vulnerabilities.json")
            if os.path.exists(cand2):
                file_path = cand2

        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as file:
                    content = file.read().strip()
                    if content.startswith("["):
                        results = json.loads(content)
                    else:
                        for line in content.splitlines():
                            if line.strip():
                                try:
                                    results.append(json.loads(line.strip()))
                                except Exception:
                                    pass
            except Exception:
                results = []

    return {
        "status": "success",
        "scan_id": active_scan_id,
        "total_vulnerabilities_found": len(results),
        "vulnerabilities": results,
        "data": results
    }

@app.get("/api/scan/{scan_id}/discovery")
def get_discovery_results(scan_id: str, db: Session = Depends(get_db)):
    """Phase 1 results: Subdomains and Open Ports queried directly from Assets table."""
    subdomains = []
    ports = []

    try:
        assets = db.query(Assets).filter(Assets.scan_id == scan_id).all()
        if assets:
            sub_set = set()
            port_set = set()
            for a in assets:
                if a.url:
                    parsed = urlparse(a.url)
                    host = parsed.hostname or (parsed.netloc.split(":")[0] if parsed.netloc else "")
                    if host:
                        sub_set.add(host)
                if a.open_ports:
                    for p in str(a.open_ports).split(","):
                        p_clean = p.strip()
                        if p_clean:
                            port_set.add(p_clean)
            subdomains = sorted(list(sub_set))
            ports = sorted(list(port_set))
    except Exception as e:
        print(f"[!] Warning: DB query error in get_discovery_results: {e}", flush=True)

    if not subdomains and not ports:
        session_dir = get_session_dir(scan_id)
        if not os.path.exists(session_dir):
            raise HTTPException(status_code=404, detail="جلسة الفحص غير موجودة.")

        sub_file = os.path.join(session_dir, "subdomains.txt")
        if os.path.exists(sub_file):
            with open(sub_file, "r", encoding="utf-8") as f:
                subdomains = [line.strip() for line in f if line.strip()]

        ports_file = os.path.join(session_dir, "ports.txt")
        if os.path.exists(ports_file):
            with open(ports_file, "r", encoding="utf-8") as f:
                ports = [line.strip() for line in f if line.strip()]

    stat = get_status(scan_id) if scan_id else {}
    target_domain = (stat or {}).get("target_domain", "")
    subdomains = prioritize_hosts(subdomains, target_domain, include_root=False)
    ports = prioritize_ports(ports, target_domain)

    return {
        "status": "success",
        "scan_id": scan_id,
        "total_subdomains": len(subdomains),
        "subdomains": subdomains,
        "total_open_ports": len(ports),
        "open_ports": ports
    }

@app.get("/api/scan/{scan_id}/endpoints")
def get_endpoints_results(scan_id: str, db: Session = Depends(get_db)):
    """Phase 2 results: Active Web URLs, Tech Stack, and Discovered API Routes from Assets."""
    active_urls = []
    api_endpoints = []

    try:
        assets = db.query(Assets).filter(Assets.scan_id == scan_id).all()
        if assets:
            for a in assets:
                ts = a.tech_stack or {}
                if a.is_api:
                    api_endpoints.append({
                        "url": a.url,
                        "status_code": ts.get("status_code", 200),
                        "path": ts.get("path", urlparse(a.url).path),
                        "content_type": ts.get("content_type", "application/json"),
                        "content_length": ts.get("content_length", 0),
                        "is_swagger_or_doc": ts.get("is_swagger_or_doc", False),
                        "is_auth_endpoint": ts.get("is_auth_endpoint", False),
                        "is_actuator": ts.get("is_actuator", False),
                    })
                else:
                    active_urls.append({
                        "url": a.url,
                        "status_code": ts.get("status_code", 200),
                        "title": ts.get("title", ""),
                        "webserver": ts.get("webserver", ""),
                        "tech": ts.get("tech", []),
                        "content_length": ts.get("content_length", 0),
                        "host": urlparse(a.url).netloc,
                    })
    except Exception as e:
        print(f"[!] Warning: DB query error in get_endpoints_results: {e}", flush=True)

    if not active_urls and not api_endpoints:
        session_dir = get_session_dir(scan_id)
        if not os.path.exists(session_dir):
            raise HTTPException(status_code=404, detail="جلسة الفحص غير موجودة.")

        urls_file = os.path.join(session_dir, "active_urls.json")
        if os.path.exists(urls_file):
            with open(urls_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.strip():
                        try:
                            active_urls.append(json.loads(line.strip()))
                        except Exception:
                            pass

        api_file = os.path.join(session_dir, "api_endpoints.json")
        if os.path.exists(api_file):
            with open(api_file, "r", encoding="utf-8") as f:
                try:
                    api_endpoints = json.load(f)
                except Exception:
                    pass

    stat = get_status(scan_id) if scan_id else {}
    target_domain = (stat or {}).get("target_domain", "")
    active_urls = prioritize_dict_records(active_urls, target_domain, key="url")
    api_endpoints = prioritize_dict_records(api_endpoints, target_domain, key="url")

    return {
        "status": "success",
        "scan_id": scan_id,
        "total_live_urls": len(active_urls),
        "live_web_services": active_urls,
        "total_api_endpoints": len(api_endpoints),
        "api_endpoints": api_endpoints
    }

@app.get("/api/scan/{scan_id}/report")
def get_executive_report(scan_id: str, db: Session = Depends(get_db)):
    """Returns a consolidated executive security report for the scan session from DB."""
    status = get_status(scan_id) or {}
    session_dir = get_session_dir(scan_id)
    if not status and not os.path.exists(session_dir):
        session_obj = db.query(ScanSessions).filter(ScanSessions.scan_id == scan_id).first()
        if not session_obj:
            raise HTTPException(status_code=404, detail="جلسة الفحص غير موجودة.")

    subdomains = []
    api_endpoints = []
    vulns = []

    # 1. Query Assets from DB
    try:
        assets = db.query(Assets).filter(Assets.scan_id == scan_id).all()
        if assets:
            sub_set = set()
            for a in assets:
                if a.url:
                    parsed = urlparse(a.url)
                    host = parsed.hostname or (parsed.netloc.split(":")[0] if parsed.netloc else "")
                    if host:
                        sub_set.add(host)
                if a.is_api:
                    ts = a.tech_stack or {}
                    api_endpoints.append({
                        "url": a.url,
                        "status_code": ts.get("status_code", 200),
                        "path": ts.get("path", urlparse(a.url).path),
                    })
            subdomains = sorted(list(sub_set))
    except Exception as e:
        print(f"[!] Warning: DB query error for Assets in get_executive_report: {e}", flush=True)

    # 2. Query Vulnerabilities from DB
    try:
        findings_rows = (
            db.query(VulnerabilityFindings, VulnerabilityCatalog)
            .outerjoin(VulnerabilityCatalog, VulnerabilityFindings.catalog_id == VulnerabilityCatalog.id)
            .filter(VulnerabilityFindings.scan_id == scan_id)
            .all()
        )
        if findings_rows:
            for finding, catalog in findings_rows:
                raw = finding.raw_output or {}
                title = (catalog.title if catalog else None) or raw.get("title", "Unknown")
                cve_id = (catalog.cve_id if catalog else None) or raw.get("cve_id")
                vulns.append({
                    "id": cve_id or raw.get("id") or f"VULN-{finding.id}",
                    "title": title,
                    "severity": (finding.severity or "info").upper(),
                    "url": finding.affected_url,
                    "raw_output": raw
                })
    except Exception as e:
        print(f"[!] Warning: DB query error for Findings in get_executive_report: {e}", flush=True)

    # Fallback to files if DB empty
    if not subdomains and os.path.exists(session_dir):
        sub_file = os.path.join(session_dir, "subdomains.txt")
        if os.path.exists(sub_file):
            with open(sub_file, "r", encoding="utf-8") as f:
                subdomains = [line.strip() for line in f if line.strip()]

    if not api_endpoints and os.path.exists(session_dir):
        api_file = os.path.join(session_dir, "api_endpoints.json")
        if os.path.exists(api_file):
            with open(api_file, "r", encoding="utf-8") as f:
                try:
                    api_endpoints = json.load(f)
                except Exception:
                    pass

    if not vulns and os.path.exists(session_dir):
        vuln_file = os.path.join(session_dir, "unified_vulnerabilities.json")
        if os.path.exists(vuln_file):
            with open(vuln_file, "r", encoding="utf-8") as f:
                try:
                    vulns = json.load(f)
                except Exception:
                    pass

    stats = status.get("stats", {}) if isinstance(status.get("stats"), dict) else {}
    severity_summary = stats.get("vuln_by_severity", {}) if isinstance(stats.get("vuln_by_severity"), dict) else {}
    if not severity_summary and vulns:
        severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulns:
            sev = (v.get("severity") or "info").lower()
            if sev in severity_summary:
                severity_summary[sev] += 1

    target_domain = status.get("target_domain")
    if not target_domain:
        try:
            s_rec = db.query(ScanSessions).filter(ScanSessions.scan_id == scan_id).first()
            if s_rec and s_rec.target:
                target_domain = s_rec.target.domain_name
        except Exception:
            pass
    target_domain = target_domain or "النطاق المستهدف"
    created_at = status.get("created_at", "")
    is_completed = status.get("is_completed", False)

    return {
        "report_title": f"YemenScan Executive Assessment Report - {target_domain}",
        "scan_metadata": {
            "scan_id": scan_id,
            "target_domain": target_domain,
            "created_at": created_at,
            "is_completed": is_completed,
            "total_subdomains": len(subdomains),
            "total_api_endpoints": len(api_endpoints),
            "total_vulnerabilities": len(vulns)
        },
        "severity_summary": severity_summary,
        "top_vulnerabilities": vulns[:10],
        "all_vulnerabilities": vulns
    }

@app.get("/api/nuclei/info")
def get_nuclei_info():
    """Returns Nuclei engine status and installed templates breakdown."""
    from core.runner import is_docker_available
    from core.stage3_vulnerabilities import get_nuclei_templates_info
    
    templates = get_nuclei_templates_info()
    categories = {}
    for t in templates:
        cat = t.get("category", "other")
        categories[cat] = categories.get(cat, 0) + 1
        
    return {
        "status": "success",
        "engine": "Nuclei v3.11.1 (Docker & Native Engine)",
        "docker_available": is_docker_available(),
        "total_templates": len(templates),
        "categories": categories,
        "templates": templates
    }

@app.post("/api/vulnerabilities/normalize")
def normalize_vulnerability_endpoint(vuln_payload: Dict[str, Any]):
    """
    Enterprise-grade Vulnerability Normalization & Enrichment endpoint.
    Standardizes CVE, CWE, CVSS v3.1, OWASP Top 10:2021 & API:2023,
    and enriches with CISA KEV and deduplication fingerprint.
    Supports both single vulnerability dict and multi-source/batch payloads.
    """
    from core.vuln_normalizer import normalize_vulnerability
    try:
        items_to_normalize = []
        if any(k in vuln_payload for k in ("nuclei", "wapiti", "vulnerabilities", "findings")):
            for k in ("nuclei", "wapiti", "vulnerabilities", "findings"):
                val = vuln_payload.get(k)
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict):
                            if "source" not in item:
                                item["source"] = "Nuclei Engine" if k == "nuclei" else "Wapiti DAST" if k == "wapiti" else "Security Scanner"
                            items_to_normalize.append(item)
            normalized_list = [normalize_vulnerability(it) for it in items_to_normalize]
            return {
                "status": "success",
                "count": len(normalized_list),
                "data": normalized_list,
                "vulnerabilities": normalized_list
            }
        else:
            normalized = normalize_vulnerability(vuln_payload)
            return {
                "status": "success",
                "data": normalized,
                "vulnerabilities": [normalized]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Normalization failed: {str(e)}")

@app.post("/api/nuclei/scan")
def scan_nuclei_endpoint(req: NucleiScanRequest):
    """Executes an on-demand targeted Nuclei scan on a URL or endpoint."""
    from core.stage3_vulnerabilities import run_standalone_nuclei
    if not req.target or len(req.target.strip()) < 4:
        raise HTTPException(status_code=400, detail="يرجى إدخال رابط هدف صالح للفحص.")
    
    try:
        clean_domain, _ = validate_target_domain(req.target, check_dns=True)
    except TargetValidationError as ve:
        raise HTTPException(status_code=ve.status_code, detail=ve.message)

    target = req.target.strip()
    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"http://{clean_domain}"
        
    findings = run_standalone_nuclei(target, category=req.category)
    return {
        "status": "success",
        "target": target,
        "category": req.category or "all",
        "total_findings": len(findings),
        "findings": findings
    }
# =====================================================================
# Strict System Prompts and Post-Processing Sanitizers for AI Reports
# =====================================================================

SYSTEM_PROMPT_EXECUTIVE = """أنت مستشار أول للأمن السيبراني ورئيس استراتيجي للأمن المعلوماتي (Chief Information Security Officer - CISO Advisor) لمنصة "YemenScan".

مهمتك كتابة "تقرير تنفيذي استراتيجي للإدارة العليا ومجلس الإدارة" باللغة العربية الفصحى الرصينة.
الجمهور المستهدف: صناع القرار، مجلس الإدارة، الرئيس التنفيذي، وعمداء الكليات الذين يحتاجون لتقييم المخاطر الكلية دون الخوض في تفاصيل برمجية.

⛔ خط أحمر وقواعد صارمة جداً (يُمنع مخالفتها تحت أي ظرف وبلا أي استثناء):
1. حظر تام للأكواد والتعليمات الفنية: يُمنع منعاً باتاً ومطلقاً كتابة أي سطر كود برمجي، أو كتل برمجية (```)، أو أوامر نظام (Shell/Bash)، أو إعدادات خوادم وتوجيهات تكوينية (مثل توجيهات Nginx كـ server_tokens، أو توجيهات Apache كـ Header set أو .htaccess، أو توجيهات IIS و PHP). لا تذكر أي شفرات برمجية إطلاقاً!
2. حظر المسارات التقنية العميقة: يُمنع كتابة مسارات الملفات البرمجية أو إعدادات الخوادم الداخلية (مثل /etc/nginx/... أو wp-content/plugins/...).
3. التركيز الحصري والمطلق على أبعاد الأعمال (Business Impact Only):
   - المخاطر المالية (Financial Risks): تقدير تكلفة توقف الخدمات، خسائر الانقطاع، تكلفة الاستجابة للحوادث، والغرامات النظامية.
   - السمعة والمكانة المؤسسية (Brand Reputation): ثقة العملاء والشركاء، الضرر الإعلامي المحتمل، والمسؤولية المؤسسية.
   - استمرارية وسير العمل (Business Continuity): مخاطر انقطاع الخدمات الرقمية الحيوية، تعطل العمليات اليومية، وسلاسل الإمداد.
   - الحوكمة والمساءلة والامتثال (Compliance & Governance): الامتثال للوائح حماية البيانات والأطر التشريعية.
4. التنسيق اللغوي: لغة استراتيجية راقية، نبرة قيادية رصينة، بعيدة تماماً عن المصطلحات المعقدة غير المفسرة.

التزم بالهيكلة التالية حصراً (Markdown):
## 📊 1. الملخص التنفيذي ومستوى الجاهزية الأمنية
[فقرة تلخص الموقف الأمني الإجمالي للنطاق ومستوى التهديد على أهداف المؤسسة]

## 📈 2. لوحة مؤشرات المخاطر المؤسسية (Risk Metrics)
- مستوى الخطر الكلي: [حرج / مرتفع / متوسط / منخفض / آمن ومحصن]
- عدد الأصول والخدمات الرقمية المفحوصة: [العدد]
- التهديدات الاستراتيجية العاجلة: [العدد]

## ⚠️ 3. تحليل الأثر المالي والتشغيلي على المؤسسة (Business Impact Analysis)
- الأثر المالي والتكاليف المحتملة: [تحليل مالي واضح للمخاطر]
- أثر السمعة وثقة المتعاملين: [تحليل أثر تسريب البيانات أو تشويه السمعة]
- استمرارية الخدمات والعمليات: [مدى استقرار الخدمات الحيوية]

## 🛡️ 4. التوصيات الاستراتيجية وحوكمة الأمن السيبراني
- قرارات الحوكمة والسياسات الأمنية: [توصيات للإدارة]
- تخصيص الميزانيات وتطوير الكفاءات: [دعم البنية التحتية والكوادر البشرية]
- خطة المتابعة والمراجعة الدورية: [إلزامية التدقيق الدوري والمراقبة المستمرة]
"""

SYSTEM_PROMPT_TECHNICAL = """أنت مهندس أمن سيبراني أول وخبير اختبار اختراق متقدم (Senior Lead Penetration Tester & Application Security Engineer) لمنصة "YemenScan".

مهمتك كتابة "تقرير أمني تقني مفصل وشامل" باللغة العربية، موجه لمديري الأنظمة (SysAdmins)، مهندسي السحابة (DevOps)، وفريق المطورين البرمجيين.

⛔ قواعد وإرشادات صارمة جداً (إلزامية للتوافق وتفادي تشوه الطباعة):
1. عزل كافة الأكواد داخل كتل برمجية مستقلة مع تحديد اللغة (Mandatory Isolated Code Blocks):
   - يجب عزل أي سطر برمجي، أو أمر شل (CLI)، أو إعدادات خادم (Nginx, Apache, IIS, Linux, PHP, Python, SQL) داخل كتلة برمجية مستقلة بثلاث علامات اقتباس خلفية (```) مع **تحديد لغة البرمجة أو الخادم إجبارياً في بداية الكتلة**، مثل:
     ```nginx
     # كود إعدادات Nginx هنا
     ```
     ```apache
     # كود إعدادات Apache هنا
     ```
     ```bash
     # أوامر الشل هنا
     ```
     ```ini
     # إعدادات PHP/Config هنا
     ```
   - يُمنع منعاً باتاً كتابة أوامر الخوادم أو الأكواد ضمن الأسطر النصية العادية لمنع تداخل الاتجاه العربي (RTL) مع الإنجليزي (LTR) عند تصدير الـ PDF.
2. التنقيط الموحد الصارم (Bullet Points Rule):
   - يُمنع منعاً باتاً استخدام الحروف العربية (مثل حرف "ه", "هـ", "أ", "ب") أو الرموز العشوائية كعلامات للقوائم النقطية.
   - يجب حصراً استخدام علامة الشرطة الإنجليزية (`- `) متبوعة بمسافة واحدة لكافة النقاط الفرعية، أو الأرقام (`1. `, `2. `) للتسلسلات المرتبة فقط.
3. الدقة الفنية والمعايير العالمية:
   - اذكر الروابط المتأثرة (URLs) بدقة كاملة.
   - اربط كل ثغرة بمعيار OWASP (Web أو API) ورقم CVE المناسب، مع تحديد مستوى الخطورة بدقة (CRITICAL / HIGH / MEDIUM / LOW / INFO).
   - توفير كود إصلاح جاهز للاستخدام المباشر لمدير النظام.

التزم بالهيكلة التالية حصراً (Markdown):
## ⚙️ 1. النظرة العامة الفنية وبصمات التقنيات (Technical Overview)
- النطاق المستهدف، عناوين IP، والمنافذ المكتشفة
- بيئات التشغيل وخوادم الويب المرصودة

## 🚨 2. السجل التفصيلي للثغرات والتهديدات التقنية (مرتبة حسب الأولوية)
[لكل ثغرة مكتشفة]:
### [اسم الثغرة بالإنجليزية والعربية] - درجة الخطورة: [CRITICAL/HIGH/MEDIUM/LOW]
- المعيار المرجعي: [OWASP A0X:2021 / CVE-XXXX-XXXX]
- الرابط المتأثر (Target URL): `[الرابط الكامل]`
- الوصف التقني وجذر المشكلة (Root Cause): [شرح فني دقيق]
- آلية الاستغلال ومؤشر الخطر: [شرح آلية الهجوم]
- كود وإعدادات المعالجة الصارمة (Remediation Config):
```[nginx/apache/bash/python/ini]
# كود الإصلاح المعزول هنا
```

## 🔧 3. دليل تحصين الخوادم وتطبيقات الويب (Hardening Blueprint)
- تحصين ترويسات الأمان وتشفير الاتصال:
```nginx
# كود الترويسات وإعدادات TLS
```
- تأمين بيئة التشغيل وتحديث الحزم:
```bash
# أوامر الفحص والتحصين
```
"""

def sanitize_executive_report(text: str) -> str:
    """
    Guarantees 100% compliance with executive report rules by scrubbing
    any stray code blocks, technical server directives, or raw configs.
    """
    if not text:
        return text
    # 1. Remove markdown code blocks completely and replace with executive summary note
    text = re.sub(
        r'```[\w]*\n[\s\S]*?```',
        '\n> *(ملاحظة أمنية: تم حجب الشفرات البرمجية وإعدادات الخوادم لالتزام التقرير بالصيغة التنفيذية للإدارة العليا)*\n',
        text
    )
    # 2. Scrub stray server directives if leaked outside code blocks
    forbidden_patterns = [
        r'^\s*(server_tokens|listen|ssl_protocols|add_header|Header\s+set|RewriteEngine)\b.*$',
        r'^\s*<VirtualHost\b.*$',
        r'^\s*</VirtualHost>.*$',
        r'^\s*<Directory\b.*$',
        r'^\s*</Directory>.*$'
    ]
    lines = []
    for line in text.splitlines():
        if any(re.search(p, line, re.IGNORECASE) for p in forbidden_patterns):
            continue
        lines.append(line)
    return "\n".join(lines).strip()

def sanitize_technical_report(text: str) -> str:
    """
    Enforces clean formatting for technical reports:
    - Normalizes bullet points to standard '-' (scrubbing random 'ه', 'هـ', '•', or '*').
    - Ensures all code blocks have language tags without altering closing fences.
    """
    if not text:
        return text
    # 1. Normalize bullet points: replace lines starting with 'ه ', 'هـ ', '• ', or '* ' with '- '
    text = re.sub(r'^[ \t]*(?:[•*]|هـ?|أ|ب)[ \t]+', '- ', text, flags=re.MULTILINE)
    
    # 2. Ensure bare opening code blocks have a language tag (default to 'text' if missing)
    def fix_code_blocks(match):
        lang = match.group(1).strip()
        body = match.group(2)
        if not lang:
            lang = "text"
        return f"```{lang}\n{body}```"

    text = re.sub(r'```([a-zA-Z0-9_-]*)[ \t]*\n([\s\S]*?)```', fix_code_blocks, text)
    return text.strip()

def generate_fallback_report(scan_id: str, r_type: str) -> str:
    """
    مُولد تقارير معياري واحترافي باللغة العربية (Offline Rule-Based Generator):
    يعمل كشبكة أمان وحصانة متقدمة عند انقطاع الإنترنت أو تعثر استدعاء خوادم Google Gemini،
    حيث يستخلص البيانات الواقعية للفحص الأمني ويبني تقريراً شاملاً وفق المعايير العالمية.
    """
    session_dir = get_session_dir(scan_id)
    status = get_status(scan_id) or {}
    domain = status.get("target_domain", "النطاق المستهدف")
    created_at = status.get("created_at", datetime.now().isoformat())
    stats = status.get("stats", {}) if isinstance(status.get("stats"), dict) else {}
    
    sub_count = stats.get("subdomains_count", 0)
    ports_count = stats.get("open_ports_count", 0)
    urls_count = stats.get("live_urls_count", 0)
    apis_count = stats.get("api_endpoints_count", 0)
    vuln_count = stats.get("vulnerabilities_count", 0)
    
    sev_stats = stats.get("vuln_by_severity", {}) if isinstance(stats.get("vuln_by_severity"), dict) else {}
    crit_count = sev_stats.get("critical", 0)
    high_count = sev_stats.get("high", 0)
    med_count = sev_stats.get("medium", 0)
    low_count = sev_stats.get("low", 0)
    info_count = sev_stats.get("info", 0)

    # Load findings
    vulns = []
    vuln_file = os.path.join(session_dir, "unified_vulnerabilities.json")
    if os.path.exists(vuln_file):
        try:
            with open(vuln_file, "r", encoding="utf-8", errors="replace") as f:
                vulns = json.load(f)
        except Exception:
            pass

    # Deduplicate findings by title and severity
    seen = set()
    unique_vulns = []
    for v in vulns:
        key = (v.get("title", ""), v.get("severity", ""))
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)

    # Determine overall risk level
    if crit_count > 0:
        overall_risk = "حرج جداً (CRITICAL)"
        risk_color = "حرج"
    elif high_count > 0:
        overall_risk = "مرتفع (HIGH)"
        risk_color = "مرتفع"
    elif med_count > 0:
        overall_risk = "متوسط (MEDIUM)"
        risk_color = "متوسط"
    elif low_count > 0:
        overall_risk = "منخفض (LOW)"
        risk_color = "منخفض"
    else:
        overall_risk = "آمن ومحصن (SECURE)"
        risk_color = "آمن ومحصن"

    if r_type == "executive":
        md = f"""## 📊 1. الملخص التنفيذي ومستوى الجاهزية الأمنية

يستعرض هذا التقرير النتائج التحليلية لعملية التقييم الأمني الشاملة التي نفذتها منظومة "YemenScan" على النطاق المؤسسي المستهدف ({domain}) وأصوله الرقمية التابعة.
تم فحص الأصول الخارجية باستخدام محركات اختبار الاختراق المتقدمة (Nuclei Engine و Wapiti DAST و Kiterunner).
أظهرت النتائج مستوى مخاطر إجمالي يُصنف بأنه **[{overall_risk}]**. تم رصد ما مجموعه **({vuln_count})** ثغرة وملاحظة أمنية موزعة عبر الخدمات الرقمية المفحوصة، مع تسجيل ({crit_count}) ثغرات حرجة و ({high_count}) ثغرات عالية الخطورة و ({med_count}) ثغرات متوسطة.
تتطلب هذه المؤشرات اتخاذ إجراءات وقائية عاجلة من قبل الإدارة الفنية لتقليص مساحة الهجوم وسد الثغرات قبل أن يتم استغلالها من قِبل جهات معادية.

## 📈 2. لوحة مؤشرات المخاطر المؤسسية (Risk Metrics)

- مستوى الخطر الكلي: [{risk_color}]
- عدد الأصول والخدمات الرقمية المفحوصة: [{sub_count} نطاقاً فرعياً، و {urls_count} خدمة ويب نشطة، و {apis_count} مسار برمجي]
- التهديدات الاستراتيجية المرصودة: [{vuln_count} ثغرة أمنية موزعة]
- مؤشر الثغرات الحرجة (Critical): [{crit_count}]
- مؤشر الثغرات عالية الخطورة (High): [{high_count}]
- مؤشر الثغرات متوسطة الخطورة (Medium): [{med_count}]
- مؤشر الملاحظات والتنبيهات (Low & Info): [{low_count + info_count}]

## ⚠️ 3. تحليل الأثر المالي والتشغيلي على المؤسسة (Business Impact Analysis)

- الأثر المالي والتكاليف المحتملة: إن استغلال الثغرات المرصودة في بيئات الإنتاج قد يؤدي إلى خسائر مالية جسيمة نتيجة توقف المعاملات الرقمية، وتكاليف الاستجابة للحوادث والتحقيق الجنائي الرقمي، فضلاً عن احتمالية فرض غرامات تنظيمية نتيجة الإخلال بضوابط حماية البيانات.
- أثر السمعة وثقة المتعاملين: تمثل الثقة الرقمية الركيزة الأساسية لسمعة المؤسسة. إن حدوث أي اختراق أو تسريب لبيانات المستخدمين سيلحق ضرراً بالغاً بالصورة الذهنية والعلامة التجارية في الأوساط العامة، مما يؤدي إلى فقدان الشركاء والعملاء.
- استمرارية الخدمات والعمليات: تشير نتائج الفحص إلى وجود نقاط ضعف قد تستغل في تعطيل الخوادم والبوابات الحيوية، مما يهدد استمرارية الأعمال اليومية ويعطل سير العمل وسلاسل الإمداد الرقمية للمؤسسة.

## 🛡️ 4. التوصيات الاستراتيجية وحوكمة الأمن السيبراني

- قرارات الحوكمة والسياسات الأمنية: اعتماد سياسة أمنية ملزمة لتأمين دورة حياة تطوير البرمجيات (SSDLC)، وتفعيل ضوابط إدارة الهوية والوصول، وفرض معايير التشفير القياسية على جميع البوابات الرقمية.
- تخصيص الميزانيات وتطوير الكفاءات: رصد ميزانيات مخصصة لأدوات المراقبة والدفاع الاستباقي، وتأهيل الفرق البرمجية وإدارات الشبكات عبر دورات مكثفة في الأمن السيبراني واختبار الاختراق.
- خطة المتابعة والمراجعة الدورية: إلزامية إجراء فحوصات أمنية واختبارات اختراق دورية شاملة (ربع سنوية) عبر منصة YemenScan لمواكبة التهديدات المتجددة وضمان استمرارية التحصين.
"""
        return md.strip()

    else:
        # Technical Report
        sub_list_str = f"- إجمالي النطاقات الفرعية المكتشفة: {sub_count}\n"
        port_list_str = f"- إجمالي المنافذ المفتوحة: {ports_count}\n"
        url_list_str = f"- إجمالي عناوين الويب والخدمات النشطة: {urls_count}\n"

        vulns_section = []
        if not unique_vulns:
            vulns_section.append("لم يتم رصد ثغرات أمنية نشطة في هذا الفحص. جميع الاختبارات القياسية اجتازت بنجاح.")
        else:
            for v in unique_vulns[:15]:
                title = v.get("title", "ثغرة أمنية غير محددة")
                sev = v.get("severity", "MEDIUM").upper()
                cat = v.get("category", "OWASP Security Misconfiguration")
                target_url = v.get("url", f"https://{domain}")
                desc = v.get("description", "تم اكتشاف ثغرة برمجية أو خطأ في إعدادات الخادم يتطلب المعالجة السريعة.")
                rem = v.get("remediation", "يرجى مراجعة إعدادات الخادم وتطبيق التحديثات والضوابط الأمنية اللازمة.")

                lang = "nginx"
                if "clickjacking" in title.lower() or "x-frame" in title.lower():
                    code = "add_header X-Frame-Options \"SAMEORIGIN\" always;\nadd_header Content-Security-Policy \"frame-ancestors 'self';\" always;"
                elif "cors" in title.lower():
                    code = f"# Whitelist only trusted application origins\nadd_header 'Access-Control-Allow-Origin' \"https://{domain}\" always;\nadd_header 'Access-Control-Allow-Credentials' 'true' always;"
                elif "csp" in title.lower() or "content-security-policy" in title.lower():
                    code = "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';\" always;"
                elif "cookie" in title.lower() or "httponly" in title.lower():
                    lang = "ini"
                    code = "session.cookie_httponly = 1\nsession.cookie_secure = 1\nsession.cookie_samesite = \"Strict\""
                else:
                    lang = "bash"
                    code = f"# التحقق من المسار وتأمين التكوينات\ncurl -I -s {target_url}\n# تطبيق التحديثات الأمنية وإعادة تشغيل الخدمة"

                item = f"""### {title} - درجة الخطورة: {sev}
- المعيار المرجعي: {cat}
- الرابط المتأثر (Target URL): `{target_url}`
- الوصف التقني وجذر المشكلة (Root Cause): {desc}
- آلية الاستغلال ومؤشر الخطر: استغلال هذه الفجوة يتيح للمهاجمين تجاوز ضوابط الحماية وتنفيذ هجمات غير مصرح بها تستهدف جلسات المستخدمين وبيانات التطبيق.
- كود وإعدادات المعالجة الصارمة (Remediation Config):
```{lang}
{code}
```"""
                vulns_section.append(item)

        vulns_joined = "\n\n".join(vulns_section)

        md = f"""## ⚙️ 1. النظرة العامة الفنية وبصمات التقنيات (Technical Overview)
- النطاق المستهدف: `{domain}`
{sub_list_str}{port_list_str}{url_list_str}- خوادم الويب وبيئات التشغيل: تم رصد الخدمات النشطة وإخضاعها لاختبارات الاستجابة وتحليل الترويسات.

## 🚨 2. السجل التفصيلي للثغرات والتهديدات التقنية (مرتبة حسب الأولوية)

{vulns_joined}

## 🔧 3. دليل تحصين الخوادم وتطبيقات الويب (Hardening Blueprint)
- تحصين ترويسات الأمان وتشفير الاتصال:
```nginx
# ترويسات الأمان الموصى بها لكافة خوادم الويب
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self';" always;
```
- تأمين بيئة التشغيل وتحديث الحزم:
```bash
# فحص وتحديث الحزم البرمجية على الخادم
sudo apt-get update && sudo apt-get upgrade -y
# فحص شهادات SSL/TLS
openssl s_client -connect {domain}:443 -tls1_2
```
"""
        return md.strip()

def parse_markdown_inline(text: str) -> str:
    text = re.sub(r'`([^`]+)`', r'<code class="ltr-inline-code" dir="ltr">\1</code>', text)
    text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', text)
    return text

def markdown_to_html(md_text: str) -> str:
    """Converts structured Markdown to clean semantic HTML for standalone export."""
    lines = md_text.splitlines()
    html_lines = []
    in_code_block = False
    code_lang = ""
    code_lines = []
    in_list = False
    in_table = False
    table_lines = []

    def render_table(t_lines):
        if not t_lines:
            return ""
        rows = []
        is_header = True
        h = ['<div class="table-responsive"><table class="report-table">']
        for row in t_lines:
            cells = [c.strip() for c in row.strip("|").split("|")]
            if all(re.match(r"^:?-+:?$", c) for c in cells):
                is_header = False
                continue
            tag = "th" if is_header else "td"
            cells_html = "".join(f"<{tag}>{parse_markdown_inline(c)}</{tag}>" for c in cells)
            rows.append(f"<tr>{cells_html}</tr>")
            if is_header:
                is_header = False
        h.extend(rows)
        h.append("</table></div>")
        return "\n".join(h)

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("```"):
            if not in_code_block:
                in_code_block = True
                code_lang = stripped[3:].strip() or "text"
                code_lines = []
                continue
            else:
                in_code_block = False
                code_content = "\n".join(code_lines)
                html_lines.append(
                    f'<pre class="ltr-code-block language-{code_lang}" dir="ltr"><code class="ltr-code" dir="ltr">{code_content}</code></pre>'
                )
                code_lines = []
                continue

        if in_code_block:
            escaped = (line.replace("&", "&amp;")
                           .replace("<", "&lt;")
                           .replace(">", "&gt;"))
            code_lines.append(escaped)
            continue

        if in_list and not stripped.startswith("- "):
            html_lines.append("</ul>")
            in_list = False

        if stripped.startswith("|") and stripped.endswith("|"):
            if not in_table:
                in_table = True
                table_lines = []
            table_lines.append(stripped)
            continue
        elif in_table:
            html_lines.append(render_table(table_lines))
            table_lines = []
            in_table = False

        if stripped.startswith("### "):
            html_lines.append(f"<h3>{parse_markdown_inline(stripped[4:])}</h3>")
        elif stripped.startswith("## "):
            html_lines.append(f"<h2>{parse_markdown_inline(stripped[3:])}</h2>")
        elif stripped.startswith("# "):
            html_lines.append(f"<h1>{parse_markdown_inline(stripped[2:])}</h1>")
        elif stripped.startswith("> "):
            html_lines.append(f"<blockquote>{parse_markdown_inline(stripped[2:])}</blockquote>")
        elif stripped.startswith("- "):
            if not in_list:
                html_lines.append("<ul>")
                in_list = True
            html_lines.append(f"<li>{parse_markdown_inline(stripped[2:])}</li>")
        elif not stripped:
            html_lines.append("")
        else:
            html_lines.append(f"<p>{parse_markdown_inline(stripped)}</p>")

    if in_code_block and code_lines:
        code_content = "\n".join(code_lines)
        html_lines.append(f'<pre class="ltr-code-block language-{code_lang}" dir="ltr"><code class="ltr-code" dir="ltr">{code_content}</code></pre>')

    if in_list:
        html_lines.append("</ul>")

    if in_table and table_lines:
        html_lines.append(render_table(table_lines))

    return "\n".join(html_lines)

def build_standalone_html(report_md: str, scan_id: str, r_type: str, status: dict) -> str:
    """Builds a beautiful, responsive, self-contained HTML assessment report."""
    body_content = markdown_to_html(report_md)
    domain = status.get("target_domain", "Target")
    stats = status.get("stats", {}) if isinstance(status.get("stats"), dict) else {}
    sub_count = stats.get("subdomains_count", 0)
    ports_count = stats.get("open_ports_count", 0)
    urls_count = stats.get("live_urls_count", 0)
    apis_count = stats.get("api_endpoints_count", 0)
    vuln_count = stats.get("vulnerabilities_count", 0)
    is_exec = (r_type == "executive")
    title = "التقرير الأمني الاستشاري للإدارة العليا (CISO Assessment)" if is_exec else "التقرير الأمني التقني للمطورين ومديري الأنظمة (Technical Remediation)"
    badge_theme = "#0284c7" if is_exec else "#6366f1"

    html = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YemenScan - {title} - {domain}</title>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        :root {{
            --primary: {badge_theme};
            --text-dark: #0f172a;
            --text-muted: #64748b;
            --border-color: #cbd5e1;
            --bg-light: #f8fafc;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Cairo', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }}
        body {{
            background-color: #f1f5f9;
            color: var(--text-dark);
            line-height: 1.7;
            padding: 24px 16px;
        }}
        .report-page {{
            max-width: 1000px;
            margin: 0 auto;
            background: #ffffff;
            border: 1px solid var(--border-color);
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.06);
            overflow: hidden;
        }}
        .action-toolbar {{
            background: #0f172a;
            color: #ffffff;
            padding: 12px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }}
        .action-toolbar h3 {{
            font-size: 0.95rem;
            color: #38bdf8;
        }}
        .action-buttons {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        .btn {{
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 700;
            cursor: pointer;
            border: none;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s;
        }}
        .btn-print {{
            background: #0284c7;
            color: #ffffff;
        }}
        .btn-print:hover {{
            background: #0369a1;
        }}
        .btn-download {{
            background: #334155;
            color: #ffffff;
        }}
        .btn-download:hover {{
            background: #475569;
        }}
        .report-header {{
            padding: 30px 36px 20px;
            border-bottom: 2px solid var(--primary);
            background: linear-gradient(180deg, #ffffff 0%, var(--bg-light) 100%);
        }}
        .brand-row {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 16px;
            margin-bottom: 20px;
        }}
        .brand-title h1 {{
            font-size: 1.6rem;
            font-weight: 900;
            color: #0f172a;
        }}
        .brand-title p {{
            font-size: 0.95rem;
            color: var(--text-muted);
            font-weight: 600;
            margin-top: 4px;
        }}
        .meta-card {{
            background: #ffffff;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 10px 16px;
            font-size: 0.82rem;
            color: #475569;
            line-height: 1.6;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 12px;
            margin-top: 20px;
        }}
        .stat-box {{
            background: #ffffff;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 10px 14px;
            text-align: center;
        }}
        .stat-box .num {{
            font-size: 1.4rem;
            font-weight: 900;
            color: var(--primary);
        }}
        .stat-box .lbl {{
            font-size: 0.75rem;
            color: var(--text-muted);
            font-weight: 700;
        }}
        .report-body {{
            padding: 36px;
            color: #1e293b;
            font-size: 10.5pt;
        }}
        .report-body h1, .report-body h2, .report-body h3 {{
            color: #0f172a;
            margin-top: 24px;
            margin-bottom: 12px;
            font-weight: 800;
        }}
        .report-body h1 {{
            font-size: 1.4rem;
            border-bottom: 2px solid var(--primary);
            padding-bottom: 6px;
        }}
        .report-body h2 {{
            font-size: 1.2rem;
            color: var(--primary);
        }}
        .report-body h3 {{
            font-size: 1.05rem;
            color: #0f172a;
        }}
        .report-body p {{
            margin-bottom: 14px;
        }}
        .report-body ul, .report-body ol {{
            margin-right: 24px;
            margin-bottom: 16px;
        }}
        .report-body li {{
            margin-bottom: 6px;
        }}
        .report-body blockquote {{
            background: #f8fafc;
            border-right: 4px solid var(--primary);
            padding: 12px 18px;
            border-radius: 6px;
            margin: 16px 0;
            color: #334155;
            font-style: italic;
        }}
        pre, .ltr-code-block {{
            direction: ltr !important;
            text-align: left !important;
            unicode-bidi: isolate !important;
            background-color: #0f172a !important;
            color: #38bdf8 !important;
            border: 1px solid #1e293b !important;
            border-radius: 8px;
            padding: 14px 18px;
            margin: 16px 0;
            font-family: Consolas, Monaco, 'Courier New', monospace;
            font-size: 0.88rem;
            line-height: 1.5;
            white-space: pre-wrap !important;
            word-wrap: break-word !important;
            overflow-wrap: break-word !important;
            overflow-x: auto;
        }}
        pre code, .ltr-code {{
            direction: ltr !important;
            text-align: left !important;
            unicode-bidi: isolate !important;
            color: #34d399 !important;
            background: transparent !important;
            padding: 0 !important;
            border: none !important;
        }}
        :not(pre) > code, .ltr-inline-code {{
            direction: ltr !important;
            text-align: left !important;
            unicode-bidi: isolate !important;
            display: inline-block;
            background: #e2e8f0;
            color: #0369a1;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: Consolas, Monaco, monospace;
            font-size: 0.85em;
        }}
        .table-responsive {{
            overflow-x: auto;
            margin: 16px 0;
        }}
        .report-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }}
        .report-table th, .report-table td {{
            border: 1px solid var(--border-color);
            padding: 10px 14px;
            text-align: right;
        }}
        .report-table th {{
            background: #f1f5f9;
            font-weight: 800;
            color: #0f172a;
        }}
        .report-table tr:nth-child(even) {{
            background: #f8fafc;
        }}
        .report-footer {{
            border-top: 1px solid var(--border-color);
            padding: 16px 36px;
            background: var(--bg-light);
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-muted);
        }}
        @media print {{
            @page {{
                size: A4 portrait;
                margin: 12mm 10mm;
            }}
            body {{
                background: #ffffff !important;
                padding: 0 !important;
            }}
            .action-toolbar {{
                display: none !important;
            }}
            .report-page {{
                border: none !important;
                box-shadow: none !important;
                max-width: 100% !important;
            }}
            pre, .ltr-code-block {{
                background-color: #0f172a !important;
                color: #38bdf8 !important;
                page-break-inside: avoid !important;
                break-inside: avoid !important;
            }}
            .report-body h1, .report-body h2, .report-body h3 {{
                page-break-after: avoid !important;
                break-after: avoid !important;
            }}
            .report-table, tr {{
                page-break-inside: avoid !important;
                break-inside: avoid !important;
            }}
        }}
    </style>
</head>
<body>
    <div class="report-page">
        <div class="action-toolbar">
            <h3>🛡️ تقرير التقييم الأمني - منظومة YemenScan</h3>
            <div class="action-buttons">
                <button onclick="window.print()" class="btn btn-print">🖨️ طباعة التقرير / حفظ PDF</button>
                <a href="/api/scan/{scan_id}/export/markdown?report_type={r_type}" class="btn btn-download">📝 تحميل Markdown</a>
                <a href="/api/scan/{scan_id}/export/json" class="btn btn-download">📊 تحميل JSON</a>
                <a href="/" class="btn btn-download">🏠 لوحة التحكم</a>
            </div>
        </div>

        <div class="report-header">
            <div class="brand-row">
                <div class="brand-title">
                    <h1>🛡️ YemenScan Cyber Security Platform</h1>
                    <p>{title}</p>
                </div>
                <div class="meta-card">
                    <div><strong>النطاق المستهدف:</strong> <span dir="ltr" style="font-family: monospace; font-weight: bold;">{domain}</span></div>
                    <div><strong>معرف الفحص:</strong> <span dir="ltr" style="font-family: monospace;">{scan_id}</span></div>
                    <div><strong>تاريخ الإصدار:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
                    <div><strong>التصنيف:</strong> <span style="color: #b91c1c; font-weight: bold;">سري ومحمي (Confidential)</span></div>
                </div>
            </div>

            <div class="stats-grid">
                <div class="stat-box">
                    <div class="num">{sub_count}</div>
                    <div class="lbl">النطاقات الفرعية</div>
                </div>
                <div class="stat-box">
                    <div class="num">{ports_count}</div>
                    <div class="lbl">المنافذ المفتوحة</div>
                </div>
                <div class="stat-box">
                    <div class="num">{urls_count}</div>
                    <div class="lbl">خدمات الويب</div>
                </div>
                <div class="stat-box">
                    <div class="num">{apis_count}</div>
                    <div class="lbl">مسارات الـ APIs</div>
                </div>
                <div class="stat-box">
                    <div class="num" style="color: #ef4444;">{vuln_count}</div>
                    <div class="lbl">الثغرات المكتشفة</div>
                </div>
            </div>
        </div>

        <div class="report-body">
            {body_content}
        </div>

        <div class="report-footer">
            تم توليد هذا التقرير الأمني آلياً عبر منصة YemenScan لإدارة سطح الهجوم واختبار الاختراق • جميع الحقوق محفوظة 2026
        </div>
    </div>
</body>
</html>"""
    return html

@app.get("/api/scan/{scan_id}/ai-report")
def generate_ai_report(
    scan_id: str, 
    refresh: bool = Query(False),
    report_type: str = Query("executive", description="Type of report: 'executive' (CISO) or 'technical' (SysAdmins)"),
    db: Optional[Session] = Depends(get_db)
):
    """
    قراءة نتائج الفحص الأمني من قاعدة البيانات (VulnerabilityFindings + VulnerabilityCatalog)
    وتمريرها إلى نماذج الذكاء الاصطناعي (Google Gemini) وتخزين التقارير الناتجة في جدول AIReports:
    1. تقرير تنفيذي للإدارة العليا (Executive - CISO Advisor): خالٍ تماماً من الأكواد ويركز على أثر الأعمال.
    2. تقرير تقني مفصل (Technical - SysAdmins & Devs): كتل برمجية معزولة للغة محددة وتنقيط قياسي موحد.
    """
    close_db_after = False
    if not isinstance(db, Session):
        db = SessionLocal()
        close_db_after = True

    try:
        session_dir = get_session_dir(scan_id)
        session_exists = os.path.exists(session_dir)
        if not session_exists:
            try:
                s_rec = db.query(ScanSessions).filter(ScanSessions.scan_id == scan_id).first()
                if s_rec:
                    session_exists = True
                    os.makedirs(session_dir, exist_ok=True)
            except Exception:
                pass

        if not session_exists:
            raise HTTPException(status_code=404, detail="جلسة الفحص غير موجودة.")

        r_type = "technical" if report_type.lower() == "technical" else "executive"

        # 0. التحقق أولاً من جدول AIReports في قاعدة البيانات إذا لم يُطلب التحديث
        if not refresh:
            try:
                db_report = db.query(AIReports).filter(AIReports.scan_id == scan_id).first()
                if db_report:
                    cached_text = db_report.technical_report if r_type == "technical" else db_report.executive_report
                    if cached_text and cached_text.strip():
                        return {
                            "status": "success",
                            "scan_id": scan_id,
                            "report_type": r_type,
                            "model_used": "Gemini (Database Cached)",
                            "cached": True,
                            "ai_report_markdown": cached_text.strip()
                        }
            except Exception as e:
                print(f"[!] Warning: DB query error for AIReports cache: {e}", flush=True)

            # فحص الملف المؤقت على القرص كإجراء احتياطي وتحديث قاعدة البيانات به
            cached_report_file = os.path.join(session_dir, f"ai_report_{r_type}.md")
            cached_meta_file = os.path.join(session_dir, f"ai_report_{r_type}.json")
            if not os.path.exists(cached_report_file) and r_type == "executive":
                legacy_f = os.path.join(session_dir, "ai_report.md")
                if os.path.exists(legacy_f):
                    cached_report_file = legacy_f

            if os.path.exists(cached_report_file):
                try:
                    with open(cached_report_file, "r", encoding="utf-8") as cf:
                        cached_md = cf.read()
                    model_used = "gemini-3.6-flash"
                    if os.path.exists(cached_meta_file):
                        with open(cached_meta_file, "r", encoding="utf-8") as mf:
                            meta = json.load(mf)
                            model_used = meta.get("model_used", model_used)
                    # حفظ التقرير الموجود على القرص إلى قاعدة البيانات للاستعلامات القادمة
                    try:
                        if r_type == "executive":
                            save_ai_report(db, scan_id, executive_report=cached_md)
                        else:
                            save_ai_report(db, scan_id, technical_report=cached_md)
                    except Exception:
                        pass

                    return {
                        "status": "success",
                        "scan_id": scan_id,
                        "report_type": r_type,
                        "model_used": model_used,
                        "cached": True,
                        "ai_report_markdown": cached_md
                    }
                except Exception:
                    pass

        # 1. جلب الثغرات المكتشفة للجلسة من جدول VulnerabilityFindings مع الربط بجدول VulnerabilityCatalog
        vulns_list = []
        try:
            rows = (
                db.query(VulnerabilityFindings, VulnerabilityCatalog)
                .outerjoin(VulnerabilityCatalog, VulnerabilityFindings.catalog_id == VulnerabilityCatalog.id)
                .filter(VulnerabilityFindings.scan_id == scan_id)
                .all()
            )
            if rows:
                for finding, catalog in rows:
                    raw = finding.raw_output or {}
                    cve_id = (catalog.cve_id if catalog else None) or raw.get("cve_id")
                    cwe_id = (catalog.cwe_id if catalog else None) or raw.get("cwe_id")
                    cvss_score = (catalog.cvss_score if catalog else None) or raw.get("cvss_score")
                    cvss_vector = (catalog.cvss_vector if catalog else None) or raw.get("cvss_vector")
                    owasp_cat = (catalog.owasp_category if catalog else None) or raw.get("category", "General")
                    title = (catalog.title if catalog else None) or raw.get("title", "Unknown Vulnerability")
                    desc = (catalog.description if catalog else None) or raw.get("description", "")
                    remediation = (catalog.standard_remediation if catalog else None) or raw.get("remediation", "")

                    vulns_list.append({
                        "id": cve_id or raw.get("id") or f"VULN-{finding.id}",
                        "title": title,
                        "severity": (finding.severity or "info").upper(),
                        "source": raw.get("source", "Vulnerability Engine"),
                        "category": owasp_cat,
                        "url": finding.affected_url,
                        "description": desc,
                        "remediation": remediation,
                        "evidence": finding.evidence,
                        "cve_id": cve_id,
                        "cwe_id": cwe_id,
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "owasp_category": owasp_cat
                    })
        except Exception as e:
            print(f"[!] Warning: DB query error for VulnerabilityFindings: {e}", flush=True)

        # Fallback إلى الملفات المحلية إذا لم تكن مسجلة في قاعدة البيانات بعد
        if not vulns_list and os.path.exists(session_dir):
            vuln_file = os.path.join(session_dir, "unified_vulnerabilities.json")
            if not os.path.exists(vuln_file):
                vuln_file = os.path.join(session_dir, "vulnerabilities.json")
            if os.path.exists(vuln_file):
                try:
                    with open(vuln_file, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read().strip()
                        if content.startswith("["):
                            vulns_list = json.loads(content)
                        else:
                            for line in content.splitlines():
                                if line.strip():
                                    try:
                                        vulns_list.append(json.loads(line.strip()))
                                    except Exception:
                                        pass
                except Exception:
                    vulns_list = []

        vulns_data = json.dumps(vulns_list, ensure_ascii=False, indent=2) if vulns_list else "[]"

        # بيانات النطاق والإحصائيات
        domain = "النطاق المستهدف"
        try:
            s_rec = db.query(ScanSessions).filter(ScanSessions.scan_id == scan_id).first()
            if s_rec and s_rec.target and s_rec.target.domain_name:
                domain = s_rec.target.domain_name
        except Exception:
            pass

        status = get_status(scan_id) or {}
        if domain == "النطاق المستهدف":
            domain = status.get("target_domain", domain)

        stats = status.get("stats", {}) if isinstance(status.get("stats"), dict) else {}
        sub_count = stats.get("subdomains_count", 0)
        ports_count = stats.get("open_ports_count", 0)
        urls_count = stats.get("live_urls_count", 0)
        apis_count = stats.get("api_endpoints_count", 0)
        vuln_count = len(vulns_list) if vulns_list else stats.get("vulnerabilities_count", 0)

        # حساب الإحصائيات من جدول Assets إذا لم تتوفر
        try:
            db_assets = db.query(Assets).filter(Assets.scan_id == scan_id).all()
            if db_assets:
                if not urls_count:
                    urls_count = len([a for a in db_assets if not a.is_api])
                if not apis_count:
                    apis_count = len([a for a in db_assets if a.is_api])
                if not sub_count:
                    sub_count = len({urlparse(a.url).netloc.split(":")[0] for a in db_assets if a.url})
                if not ports_count:
                    ports_count = len({a.open_ports for a in db_assets if a.open_ports})
        except Exception:
            pass

        has_vulns = bool(vulns_list and len(vulns_list) > 0)
        if not has_vulns:
            vulns_data_summary = f"""ملخص الفحص الأمني (لا توجد ثغرات مكشوفة):
- النطاق المستهدف: {domain}
- إجمالي النطاقات الفرعية المكتشفة: {sub_count}
- إجمالي المنافذ المفتوحة: {ports_count}
- إجمالي عناوين الويب النشطة: {urls_count}
- إجمالي واجهات برمجة التطبيقات (APIs) المفحوصة: {apis_count}
- حالة الثغرات: تم اجتياز اختبارات فحص الثغرات (Nuclei & Wapiti) بنجاح دون رصد مؤشرات اختراق نشطة (0 Vulnerabilities)."""
        else:
            vulns_data_summary = f"""بيانات الفحص الأمني المكتشفة (JSON):
```json
{vulns_data}
```"""

        # 2. الحصول على مفتاح GEMINI_API_KEY
        api_key = get_gemini_api_key()

        # 3. اختيار System Prompt وموجه المستخدم بدقة بحسب نوع التقرير
        if r_type == "executive":
            system_prompt = SYSTEM_PROMPT_EXECUTIVE
            user_prompt = f"""قم بتحليل نتائج الفحص الأمني التالية للنطاق المستهدف ({domain}) وكتابة التقرير التنفيذي للإدارة العليا:

{vulns_data_summary}

تذكير حاسم: يُمنع منعاً باتاً كتابة أي كود برمجي أو أوامر شل أو إعدادات خوادم فنية في هذا التقرير، والتركيز بالكامل على مخاطر الأعمال والسمعة والتكاليف المالية."""
        else:
            system_prompt = SYSTEM_PROMPT_TECHNICAL
            user_prompt = f"""قم بتحليل نتائج الفحص الأمني التالية للنطاق المستهدف ({domain}) وكتابة التقرير التقني المفصل:

{vulns_data_summary}

تذكير حاسم: ضع جميع الأكواد وإعدادات الإصلاح داخل كتل برمجية معزولة (```) محددة اللغة (nginx, apache, bash, ini...)، واستخدم حصراً علامة (-) للقوائم النقطية."""

        # 4. قائمة النماذج المرشحة مع دعم التبديل التلقائي بدءاً من النماذج المدعومة حالياً
        candidate_models = [
            "gemini-3.6-flash",
            "gemini-3.5-flash",
            "gemini-2.5-flash"
        ]

        report_markdown = None
        successful_model = None

        import requests

        if api_key:
            for model_name in candidate_models:
                try:
                    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
                    headers = {"Content-Type": "application/json"}
                    payload = {
                        "system_instruction": {
                            "parts": [{"text": system_prompt}]
                        },
                        "contents": [
                            {"parts": [{"text": user_prompt}]}
                        ],
                        "generationConfig": {
                            "temperature": 0.2,
                            "topP": 0.85,
                            "maxOutputTokens": 4096
                        }
                    }
                    res = requests.post(url, headers=headers, json=payload, timeout=8)
                    if res.status_code == 200:
                        res_data = res.json()
                        candidates = res_data.get("candidates", [])
                        if candidates:
                            parts = candidates[0].get("content", {}).get("parts", [])
                            if parts and "text" in parts[0] and parts[0]["text"].strip():
                                report_markdown = parts[0]["text"].strip()
                                successful_model = model_name
                                break
                except Exception:
                    pass

        # 5. شبكة الأمان الشاملة (Fallback Engine): إذا تعثر الاتصال الخارجي، نولد تقريراً نموذجياً من البيانات المحلية
        if not report_markdown:
            report_markdown = generate_fallback_report(scan_id, r_type)
            successful_model = "YemenScan Rule-Based Report Engine (Offline Fallback)"

        # 6. تطبيق التعقيم والتنظيف البرمجي الصارم (Sanitization Guardrails)
        if r_type == "executive":
            report_markdown = sanitize_executive_report(report_markdown)
        else:
            report_markdown = sanitize_technical_report(report_markdown)

        # 7. حفظ التقرير في جدول AIReports في قاعدة البيانات
        try:
            if r_type == "executive":
                save_ai_report(db, scan_id, executive_report=report_markdown)
            else:
                save_ai_report(db, scan_id, technical_report=report_markdown)
        except Exception as e:
            print(f"[!] Warning: Failed to save AI report to DB for scan_id {scan_id}: {e}", flush=True)

        # 8. حفظ التقرير في مجلد الجلسة كمرجع محلي متزامن
        try:
            cached_report_file = os.path.join(session_dir, f"ai_report_{r_type}.md")
            cached_meta_file = os.path.join(session_dir, f"ai_report_{r_type}.json")
            with open(cached_report_file, "w", encoding="utf-8") as cf:
                cf.write(report_markdown)
            with open(cached_meta_file, "w", encoding="utf-8") as mf:
                json.dump({
                    "scan_id": scan_id,
                    "report_type": r_type,
                    "model_used": successful_model,
                    "generated_at": datetime.now().isoformat()
                }, mf, ensure_ascii=False, indent=2)
        except Exception:
            pass

        return {
            "status": "success",
            "scan_id": scan_id,
            "report_type": r_type,
            "model_used": successful_model,
            "cached": False,
            "ai_report_markdown": report_markdown
        }
    finally:
        if close_db_after:
            db.close()

@app.get("/api/scan/{scan_id}/export/markdown")
def export_scan_markdown(
    scan_id: str,
    report_type: str = Query("executive", description="'executive' or 'technical'"),
    db: Session = Depends(get_db)
):
    """تنزيل التقرير الأمني بصيغة Markdown (.md) مع ترويسات التنزيل المباشر."""
    r_type = "technical" if report_type.lower() == "technical" else "executive"
    session_dir = get_session_dir(scan_id)
    content = None

    # Check DB AIReports first
    try:
        report_record = db.query(AIReports).filter(AIReports.scan_id == scan_id).first()
        if report_record:
            cached_text = report_record.technical_report if r_type == "technical" else report_record.executive_report
            if cached_text and cached_text.strip():
                content = cached_text.strip()
    except Exception as e:
        print(f"[!] Warning: DB query error for AIReports in export_scan_markdown: {e}", flush=True)

    # Check file on disk if not in DB
    if not content:
        report_file = os.path.join(session_dir, f"ai_report_{r_type}.md")
        if os.path.exists(report_file):
            try:
                with open(report_file, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                pass

    # Generate if not found
    if not content:
        res = generate_ai_report(scan_id=scan_id, refresh=False, report_type=r_type, db=db)
        content = res.get("ai_report_markdown", "") if isinstance(res, dict) else ""

    if not content:
        content = generate_fallback_report(scan_id, r_type)

    filename = f"YemenScan_{r_type.capitalize()}_Report_{scan_id}.md"
    return Response(
        content=content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@app.get("/api/scan/{scan_id}/export/html")
def export_scan_html(
    scan_id: str,
    report_type: str = Query("executive", description="'executive' or 'technical'"),
    db: Session = Depends(get_db)
):
    """توليد واستعراض تقرير أمني HTML متكامل ومستقل بذاته وجاهز للطباعة الفورية."""
    status = get_status(scan_id) or {}
    r_type = "technical" if report_type.lower() == "technical" else "executive"
    session_dir = get_session_dir(scan_id)
    content = None

    # Check DB AIReports first
    try:
        report_record = db.query(AIReports).filter(AIReports.scan_id == scan_id).first()
        if report_record:
            cached_text = report_record.technical_report if r_type == "technical" else report_record.executive_report
            if cached_text and cached_text.strip():
                content = cached_text.strip()
    except Exception as e:
        print(f"[!] Warning: DB query error for AIReports in export_scan_html: {e}", flush=True)

    # Check file on disk if not in DB
    if not content:
        report_file = os.path.join(session_dir, f"ai_report_{r_type}.md")
        if os.path.exists(report_file):
            try:
                with open(report_file, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                pass

    # Generate if not found
    if not content:
        res = generate_ai_report(scan_id=scan_id, refresh=False, report_type=r_type, db=db)
        content = res.get("ai_report_markdown", "") if isinstance(res, dict) else ""

    if not content:
        content = generate_fallback_report(scan_id, r_type)

    html_content = build_standalone_html(content, scan_id, r_type, status)
    filename = f"YemenScan_{r_type.capitalize()}_Report_{scan_id}.html"
    return HTMLResponse(
        content=html_content,
        headers={"Content-Disposition": f'inline; filename="{filename}"'}
    )

@app.get("/api/scan/{scan_id}/export/json")
def export_scan_json(
    scan_id: str,
    report_type: Optional[str] = Query(None, description="Optional filter: 'executive' or 'technical'"),
    db: Session = Depends(get_db)
):
    """تصدير شامل لكافة بيانات التقييم الأمني والتقارير التنفيذية والتقنية بصيغة JSON مهيكلة."""
    status = get_status(scan_id) or {}
    session_dir = get_session_dir(scan_id)

    # 1. Assets from DB
    subdomains = []
    ports = []
    active_urls = []
    api_endpoints = []
    try:
        assets = db.query(Assets).filter(Assets.scan_id == scan_id).all()
        if assets:
            sub_set = set()
            port_set = set()
            for a in assets:
                if a.url:
                    parsed = urlparse(a.url)
                    host = parsed.hostname or (parsed.netloc.split(":")[0] if parsed.netloc else "")
                    if host:
                        sub_set.add(host)
                if a.open_ports:
                    for p in str(a.open_ports).split(","):
                        if p.strip():
                            port_set.add(p.strip())
                ts = a.tech_stack or {}
                if a.is_api:
                    api_endpoints.append({
                        "url": a.url,
                        "status_code": ts.get("status_code", 200),
                        "path": ts.get("path", urlparse(a.url).path),
                        "content_type": ts.get("content_type", "application/json"),
                    })
                else:
                    active_urls.append({
                        "url": a.url,
                        "status_code": ts.get("status_code", 200),
                        "title": ts.get("title", ""),
                        "webserver": ts.get("webserver", ""),
                        "tech": ts.get("tech", []),
                    })
            subdomains = sorted(list(sub_set))
            ports = sorted(list(port_set))
    except Exception as e:
        print(f"[!] Warning: DB query error in export_scan_json: {e}", flush=True)

    # Fallback to files if DB assets were empty
    if not subdomains and os.path.exists(session_dir):
        sub_file = os.path.join(session_dir, "subdomains.txt")
        if os.path.exists(sub_file):
            with open(sub_file, "r", encoding="utf-8") as f:
                subdomains = [line.strip() for line in f if line.strip()]

    if not ports and os.path.exists(session_dir):
        ports_file = os.path.join(session_dir, "ports.txt")
        if os.path.exists(ports_file):
            with open(ports_file, "r", encoding="utf-8") as f:
                ports = [line.strip() for line in f if line.strip()]

    if not active_urls and os.path.exists(session_dir):
        urls_file = os.path.join(session_dir, "active_urls.json")
        if os.path.exists(urls_file):
            with open(urls_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.strip():
                        try:
                            active_urls.append(json.loads(line.strip()))
                        except Exception:
                            pass

    if not api_endpoints and os.path.exists(session_dir):
        api_file = os.path.join(session_dir, "api_endpoints.json")
        if os.path.exists(api_file):
            with open(api_file, "r", encoding="utf-8") as f:
                try:
                    api_endpoints = json.load(f)
                except Exception:
                    pass

    # 2. Vulnerabilities from DB
    vulns = []
    try:
        rows = (
            db.query(VulnerabilityFindings, VulnerabilityCatalog)
            .outerjoin(VulnerabilityCatalog, VulnerabilityFindings.catalog_id == VulnerabilityCatalog.id)
            .filter(VulnerabilityFindings.scan_id == scan_id)
            .all()
        )
        if rows:
            for finding, catalog in rows:
                raw = finding.raw_output or {}
                cve_id = (catalog.cve_id if catalog else None) or raw.get("cve_id")
                vulns.append({
                    "id": cve_id or raw.get("id") or f"VULN-{finding.id}",
                    "title": (catalog.title if catalog else None) or raw.get("title", "Unknown"),
                    "severity": (finding.severity or "info").upper(),
                    "url": finding.affected_url,
                    "cve_id": cve_id,
                    "cwe_id": catalog.cwe_id if catalog else None,
                    "cvss_score": catalog.cvss_score if catalog else None,
                    "owasp_category": catalog.owasp_category if catalog else None,
                    "evidence": finding.evidence,
                    "raw_output": raw
                })
    except Exception as e:
        print(f"[!] Warning: DB query error for vulns in export_scan_json: {e}", flush=True)

    if not vulns and os.path.exists(session_dir):
        vuln_file = os.path.join(session_dir, "unified_vulnerabilities.json")
        if os.path.exists(vuln_file):
            try:
                with open(vuln_file, "r", encoding="utf-8", errors="replace") as f:
                    vulns = json.load(f)
            except Exception:
                pass

    # 3. Cached Reports from DB
    reports = {}
    try:
        db_rep = db.query(AIReports).filter(AIReports.scan_id == scan_id).first()
        if db_rep:
            if db_rep.executive_report:
                reports["executive"] = db_rep.executive_report
            if db_rep.technical_report:
                reports["technical"] = db_rep.technical_report
    except Exception:
        pass

    for rt in ["executive", "technical"]:
        if rt not in reports and os.path.exists(session_dir):
            rf = os.path.join(session_dir, f"ai_report_{rt}.md")
            if os.path.exists(rf):
                try:
                    with open(rf, "r", encoding="utf-8") as f:
                        reports[rt] = f.read()
                except Exception:
                    pass

    target_domain = status.get("target_domain")
    if not target_domain:
        try:
            s_rec = db.query(ScanSessions).filter(ScanSessions.scan_id == scan_id).first()
            if s_rec and s_rec.target:
                target_domain = s_rec.target.domain_name
        except Exception:
            pass
    target_domain = target_domain or ""

    export_data = {
        "assessment_meta": {
            "platform": "YemenScan Cyber Security Platform",
            "version": "2.0.0",
            "scan_id": scan_id,
            "target_domain": target_domain,
            "created_at": status.get("created_at", ""),
            "exported_at": datetime.now().isoformat(),
            "status": status.get("current_stage", ""),
            "is_completed": status.get("is_completed", False)
        },
        "stats": status.get("stats", {
            "subdomains_count": len(subdomains),
            "open_ports_count": len(ports),
            "live_urls_count": len(active_urls),
            "api_endpoints_count": len(api_endpoints),
            "vulnerabilities_count": len(vulns),
        }),
        "surface_discovery": {
            "subdomains_count": len(subdomains),
            "subdomains": subdomains,
            "open_ports_count": len(ports),
            "open_ports": ports
        },
        "web_probing": {
            "live_services_count": len(active_urls),
            "live_services": active_urls,
            "api_endpoints_count": len(api_endpoints),
            "api_endpoints": api_endpoints
        },
        "vulnerabilities": {
            "total_count": len(vulns),
            "findings": vulns
        },
        "reports": reports
    }
    
    filename = f"YemenScan_Full_Assessment_{scan_id}.json"
    return Response(
        content=json.dumps(export_data, ensure_ascii=False, indent=2),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )




