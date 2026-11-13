"""
Data Ingestion Service for YemenScan.

Provides functions to parse, correlate, and persist scan results into
the normalized relational database schema (PostgreSQL / SQLite).
"""

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

# Ensure root directory is in sys.path when executed directly or imported
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from sqlalchemy.orm import Session
from models import (
    Targets,
    ScanSessions,
    Assets,
    VulnerabilityCatalog,
    VulnerabilityFindings,
    AIReports,
    SystemSettings,
)
from core.vuln_normalizer import normalize_vulnerability

logger = logging.getLogger("yemenscan.db_service")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def create_target_and_session(
    db: Session, domain: str, scan_id: str
) -> Tuple[Targets, ScanSessions]:
    """
    Check if a target already exists by domain_name; create it if absent.
    Create a new record in ScanSessions with status 'running' and current start time.

    :param db: Active SQLAlchemy Session
    :param domain: Target domain name (e.g., example.com)
    :param scan_id: Unique scan identifier (e.g., scan_20260919_120000_abc123)
    :return: Tuple containing (Targets, ScanSessions)
    """
    try:
        clean_domain = domain.strip().lower()
        if "://" in clean_domain:
            clean_domain = urlparse(clean_domain).netloc or clean_domain
        clean_domain = clean_domain.split(":")[0]

        now_utc = datetime.now(timezone.utc)

        # 1. Check or create Target
        target = db.query(Targets).filter(Targets.domain_name == clean_domain).first()
        if not target:
            logger.info("Creating new Target record for domain: %s", clean_domain)
            target = Targets(
                domain_name=clean_domain,
                last_scanned_at=now_utc,
                created_at=now_utc,
            )
            db.add(target)
            db.flush()
        else:
            logger.info("Found existing Target id=%d for domain: %s", target.id, clean_domain)
            target.last_scanned_at = now_utc

        # 2. Check or create ScanSession
        scan_session = (
            db.query(ScanSessions).filter(ScanSessions.scan_id == scan_id).first()
        )
        if not scan_session:
            logger.info("Creating new ScanSession record: %s (Target ID: %d)", scan_id, target.id)
            scan_session = ScanSessions(
                scan_id=scan_id,
                target_id=target.id,
                status="running",
                current_stage="running",
                progress=0,
                started_at=now_utc,
                completed_at=None,
            )
            db.add(scan_session)
        else:
            logger.info("Updating existing ScanSession record: %s", scan_id)
            scan_session.target_id = target.id
            scan_session.status = "running"
            scan_session.current_stage = "running"
            scan_session.started_at = now_utc
            scan_session.completed_at = None

        db.commit()
        db.refresh(target)
        db.refresh(scan_session)
        return target, scan_session

    except Exception as exc:
        db.rollback()
        logger.error("Failed in create_target_and_session for %s / %s: %s", domain, scan_id, exc)
        raise exc


def _extract_port(url_str: str, default_port: Optional[str] = None) -> Optional[str]:
    """Helper to extract port from URL or fallback."""
    if default_port and str(default_port).strip():
        return str(default_port).strip()
    try:
        parsed = urlparse(url_str)
        if parsed.port:
            return str(parsed.port)
        if parsed.scheme == "https":
            return "443"
        if parsed.scheme == "http":
            return "80"
    except Exception:
        pass
    return None


def save_discovered_assets(
    db: Session,
    scan_id: str,
    active_urls_data: List[Union[Dict[str, Any], str]],
    api_endpoints_data: List[Union[Dict[str, Any], str]],
) -> List[Assets]:
    """
    Process HTTPX (web alive) and Kiterunner (API endpoints) outputs and save them to the Assets table.
    Eliminates duplicates per scan_id and handles tech_stack metadata as JSONB.

    :param db: Active SQLAlchemy Session
    :param scan_id: Unique scan identifier
    :param active_urls_data: List of HTTPX result dicts or URL strings
    :param api_endpoints_data: List of Kiterunner result dicts or URL strings
    :return: List of Assets saved or updated
    """
    try:
        active_urls_data = active_urls_data or []
        api_endpoints_data = api_endpoints_data or []

        # Load existing assets for this scan_id to allow safe deduplication/updates
        existing_assets = {
            asset.url: asset
            for asset in db.query(Assets).filter(Assets.scan_id == scan_id).all()
        }

        saved_assets: List[Assets] = []

        # 1. Process active_urls_data (general web assets)
        for item in active_urls_data:
            status_code = None
            if isinstance(item, str):
                url = item.strip()
                if not url:
                    continue
                port = _extract_port(url)
                tech_stack = {}
            elif isinstance(item, dict):
                url = item.get("url") or item.get("input", "")
                url = url.strip()
                if not url:
                    continue
                port = _extract_port(url, str(item.get("port", "")))
                raw_sc = item.get("status_code")
                if raw_sc is not None:
                    try:
                        status_code = int(raw_sc)
                    except (ValueError, TypeError):
                        status_code = None
                tech_stack = {
                    "title": item.get("title"),
                    "webserver": item.get("webserver"),
                    "tech": item.get("tech", []),
                    "status_code": status_code,
                    "content_length": item.get("content_length"),
                    "cpe": item.get("cpe", []),
                }
                # Filter out None values
                tech_stack = {k: v for k, v in tech_stack.items() if v is not None}
            else:
                continue

            # Clamp URL to max 2048 chars
            url = url[:2048]

            if url in existing_assets:
                asset = existing_assets[url]
                if port and not asset.open_ports:
                    asset.open_ports = port
                if status_code is not None and not asset.status_code:
                    asset.status_code = status_code
                if not asset.asset_type:
                    asset.asset_type = "web_service"
                if tech_stack:
                    current_stack = asset.tech_stack or {}
                    current_stack.update(tech_stack)
                    asset.tech_stack = current_stack
            else:
                asset = Assets(
                    scan_id=scan_id,
                    url=url,
                    open_ports=port,
                    tech_stack=tech_stack,
                    is_api=False,
                    asset_type="web_service",
                    status_code=status_code,
                )
                db.add(asset)
                existing_assets[url] = asset
            saved_assets.append(asset)

        # 2. Process api_endpoints_data (API endpoints)
        for item in api_endpoints_data:
            status_code = None
            if isinstance(item, str):
                url = item.strip()
                if not url:
                    continue
                port = _extract_port(url)
                tech_stack = {"type": "api_endpoint"}
            elif isinstance(item, dict):
                url = item.get("url") or ""
                url = url.strip()
                if not url:
                    continue
                port = _extract_port(url, str(item.get("port", "")))
                raw_sc = item.get("status_code")
                if raw_sc is not None:
                    try:
                        status_code = int(raw_sc)
                    except (ValueError, TypeError):
                        status_code = None
                tech_stack = {
                    "path": item.get("path"),
                    "status_code": status_code,
                    "content_type": item.get("content_type"),
                    "is_swagger_or_doc": item.get("is_swagger_or_doc", False),
                    "is_auth_endpoint": item.get("is_auth_endpoint", False),
                    "is_actuator": item.get("is_actuator", False),
                }
                tech_stack = {k: v for k, v in tech_stack.items() if v is not None}
            else:
                continue

            # Clamp URL to max 2048 chars
            url = url[:2048]

            if url in existing_assets:
                asset = existing_assets[url]
                asset.is_api = True
                asset.asset_type = "api_endpoint"
                if status_code is not None:
                    asset.status_code = status_code
                if tech_stack:
                    current_stack = asset.tech_stack or {}
                    current_stack.update(tech_stack)
                    asset.tech_stack = current_stack
            else:
                asset = Assets(
                    scan_id=scan_id,
                    url=url,
                    open_ports=port,
                    tech_stack=tech_stack,
                    is_api=True,
                    asset_type="api_endpoint",
                    status_code=status_code,
                )
                db.add(asset)
                existing_assets[url] = asset
            saved_assets.append(asset)

        db.commit()
        logger.info("Successfully persisted %d assets for scan_id: %s", len(saved_assets), scan_id)
        return saved_assets

    except Exception as exc:
        db.rollback()
        logger.error("Failed to save assets for scan_id %s: %s", scan_id, exc)
        raise exc


def _get_classification(data: Dict[str, Any]) -> Dict[str, Any]:
    """Helper to extract classification dict whether at root level or nested inside info."""
    classif = data.get("classification")
    if isinstance(classif, dict):
        return classif
    info = data.get("info")
    if isinstance(info, dict):
        classif = info.get("classification")
        if isinstance(classif, dict):
            return classif
    return {}


def _parse_cve(data: Dict[str, Any]) -> Optional[str]:
    """Helper to extract CVE ID from varied vulnerability dictionary formats."""
    # Check direct keys
    for key in ("cve_id", "cve", "cve-id"):
        val = data.get(key)
        if isinstance(val, list) and val:
            return str(val[0]).strip().upper()
        if isinstance(val, str) and val.strip():
            return val.strip().upper()

    # Check classification (root or nested)
    classif = _get_classification(data)
    if classif:
        val = classif.get("cve-id") or classif.get("cve_id")
        if isinstance(val, list) and val:
            return str(val[0]).strip().upper()
        if isinstance(val, str) and val.strip():
            return val.strip().upper()

    # Try regex on id, title, or description
    search_space = f"{data.get('id', '')} {data.get('title', '')} {data.get('description', '')}"
    match = re.search(r"\b(CVE-\d{4}-\d{4,7})\b", search_space, re.IGNORECASE)
    if match:
        return match.group(1).upper()

    return None


def _parse_cwe(data: Dict[str, Any]) -> Optional[str]:
    """Helper to extract CWE ID from vulnerability dictionary."""
    for key in ("cwe_id", "cwe", "cwe-id"):
        val = data.get(key)
        if isinstance(val, list) and val:
            return str(val[0]).strip().upper()
        if isinstance(val, str) and val.strip():
            return val.strip().upper()

    classif = _get_classification(data)
    if classif:
        val = classif.get("cwe-id") or classif.get("cwe_id")
        if isinstance(val, list) and val:
            return str(val[0]).strip().upper()
        if isinstance(val, str) and val.strip():
            return val.strip().upper()

    search_space = f"{data.get('id', '')} {data.get('title', '')} {data.get('category', '')}"
    match = re.search(r"\b(CWE-\d+)\b", search_space, re.IGNORECASE)
    if match:
        return match.group(1).upper()

    return None


def _parse_cvss(data: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
    """Helper to extract CVSS score and vector."""
    score = None
    vector = None

    # Score
    raw_score = data.get("cvss_score") or data.get("cvss-score")
    classif = _get_classification(data)
    if raw_score is None and classif:
        raw_score = classif.get("cvss-score") or classif.get("cvss_score")
        vector = classif.get("cvss-metrics") or classif.get("cvss_vector")

    if raw_score is not None:
        try:
            score = float(raw_score)
        except (ValueError, TypeError):
            score = None

    if not vector:
        vector = data.get("cvss_vector") or data.get("cvss-metrics")
        if not vector and classif:
            vector = classif.get("cvss-metrics") or classif.get("cvss_vector")

    return score, str(vector) if vector else None


def _parse_owasp(data: Dict[str, Any]) -> Optional[str]:
    """Helper to extract OWASP category."""
    if data.get("owasp_category"):
        return str(data["owasp_category"])

    category = data.get("category")
    if category and "OWASP" in str(category):
        return str(category)

    classif = _get_classification(data)
    if classif:
        owasp = classif.get("owasp-top10") or classif.get("owasp") or classif.get("owasp_category")
        if isinstance(owasp, list) and owasp:
            return str(owasp[0]).strip()
        if isinstance(owasp, str) and owasp.strip():
            return owasp.strip()

    return str(category) if category else None


def get_or_create_catalog_entry(
    db: Session, vuln_data: Dict[str, Any]
) -> VulnerabilityCatalog:
    """
    Finds or creates a master record in VulnerabilityCatalog.
    Matches by cve_id first (if available), then by title.

    :param db: Active SQLAlchemy Session
    :param vuln_data: Dictionary representing the vulnerability finding
    :return: An instance of VulnerabilityCatalog
    """
    norm = normalize_vulnerability(vuln_data)
    cve_id = norm.get("cve_id")
    cwe_id = norm.get("cwe_id")
    cvss_score = norm.get("cvss_score")
    cvss_vector = norm.get("cvss_vector")
    owasp_category = norm.get("owasp_category")
    catalog_severity = norm.get("severity", "info").lower()[:20]
    title = norm.get("title", "Unknown Vulnerability")[:500]
    description = norm.get("description", "")
    remediation = norm.get("standard_remediation", "")

    # Safe length clamping for catalog strings
    if cve_id:
        cve_id = cve_id[:50]
    if cwe_id:
        cwe_id = cwe_id[:50]
    if cvss_vector:
        cvss_vector = str(cvss_vector)[:100]
    if owasp_category:
        owasp_category = str(owasp_category)[:255]

    # Extract references
    info = vuln_data.get("info", {}) if isinstance(vuln_data.get("info"), dict) else {}
    raw_refs = (
        vuln_data.get("reference")
        or vuln_data.get("references")
        or info.get("reference")
        or info.get("references")
    )
    reference_links = None
    if isinstance(raw_refs, list):
        reference_links = [str(r).strip() for r in raw_refs if r]
    elif isinstance(raw_refs, str) and raw_refs.strip():
        reference_links = [raw_refs.strip()]

    catalog_entry: Optional[VulnerabilityCatalog] = None

    # Try matching by cve_id if available
    if cve_id:
        catalog_entry = (
            db.query(VulnerabilityCatalog)
            .filter(VulnerabilityCatalog.cve_id == cve_id)
            .first()
        )

    # Try matching by title if not found by cve_id
    if not catalog_entry and title:
        catalog_entry = (
            db.query(VulnerabilityCatalog)
            .filter(VulnerabilityCatalog.title == title)
            .first()
        )

    # If already exists, enrich with any newly available fields and return
    if catalog_entry:
        updated = False
        if catalog_entry.cvss_score is None and cvss_score is not None:
            catalog_entry.cvss_score = cvss_score
            updated = True
        if not catalog_entry.cvss_vector and cvss_vector:
            catalog_entry.cvss_vector = cvss_vector
            updated = True
        if not catalog_entry.cwe_id and cwe_id:
            catalog_entry.cwe_id = cwe_id
            updated = True
        if not catalog_entry.owasp_category and owasp_category:
            catalog_entry.owasp_category = owasp_category
            updated = True
        if not catalog_entry.standard_remediation and remediation:
            catalog_entry.standard_remediation = remediation
            updated = True
        if not catalog_entry.severity and catalog_severity:
            catalog_entry.severity = catalog_severity
            updated = True
        if not catalog_entry.reference_links and reference_links:
            catalog_entry.reference_links = reference_links
            updated = True
        if updated:
            db.flush()
        return catalog_entry

    # Create new catalog entry
    catalog_entry = VulnerabilityCatalog(
        cve_id=cve_id,
        cwe_id=cwe_id,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        owasp_category=owasp_category,
        severity=catalog_severity,
        reference_links=reference_links,
        title=title,
        description=description,
        standard_remediation=remediation,
    )
    db.add(catalog_entry)
    db.flush()  # Generates catalog_entry.id while keeping transaction open

    return catalog_entry


def ingest_vulnerabilities(
    db: Session, scan_id: str, vulnerabilities_list: List[Dict[str, Any]]
) -> List[VulnerabilityFindings]:
    """
    Iterates over a list of vulnerability findings, links each to a
    VulnerabilityCatalog entry, and records the finding in VulnerabilityFindings.

    :param db: Active SQLAlchemy Session
    :param scan_id: Unique scan identifier
    :param vulnerabilities_list: List of vulnerability dictionaries
    :return: List of newly added VulnerabilityFindings
    """
    try:
        created_findings: List[VulnerabilityFindings] = []

        for vuln in vulnerabilities_list:
            if not isinstance(vuln, dict):
                continue

            catalog_entry = get_or_create_catalog_entry(db, vuln)
            norm = normalize_vulnerability(vuln)

            # Extract affected URL (clamped to max 2048 chars)
            raw_url = (
                norm.get("affected_url")
                or vuln.get("url")
                or vuln.get("matched-at")
                or vuln.get("matched_at")
                or vuln.get("host")
                or ""
            )
            affected_url = str(raw_url).strip()[:2048]

            # Calibrated severity from CVSS/Normalizer
            severity = norm.get("severity", "info").lower()
            if severity not in {"critical", "high", "medium", "low", "info"}:
                severity = "info"

            # Extract source and status
            info_dict = vuln.get("info", {}) if isinstance(vuln.get("info"), dict) else {}
            source = str(
                vuln.get("source")
                or vuln.get("tool")
                or vuln.get("engine")
                or info_dict.get("author")
                or "Vulnerability Engine"
            ).strip()[:100]
            status = str(vuln.get("status") or "open").strip()[:50]

            # Extract evidence
            evidence = (
                vuln.get("evidence")
                or vuln.get("curl-command")
                or vuln.get("curl_command")
                or str(vuln.get("extracted-results", ""))
                or ""
            )
            if not isinstance(evidence, str):
                evidence = str(evidence)

            # Enrich raw output with enterprise fingerprint & CISA KEV flag
            finding_raw = dict(vuln)
            finding_raw["fingerprint"] = norm.get("fingerprint")
            finding_raw["is_cisa_kev"] = norm.get("is_cisa_kev", False)
            finding_raw["owasp_category"] = norm.get("owasp_category")
            finding_raw["owasp_api_category"] = norm.get("owasp_api_category")

            finding = VulnerabilityFindings(
                scan_id=scan_id,
                catalog_id=catalog_entry.id if catalog_entry else None,
                affected_url=affected_url,
                severity=severity,
                source=source,
                status=status,
                evidence=evidence,
                raw_output=finding_raw,
                discovered_at=datetime.now(timezone.utc),
            )
            db.add(finding)
            created_findings.append(finding)

        db.commit()
        logger.info(
            "Successfully ingested %d vulnerabilities for scan_id: %s",
            len(created_findings),
            scan_id,
        )
        return created_findings

    except Exception as exc:
        db.rollback()
        logger.error("Failed to ingest vulnerabilities for scan_id %s: %s", scan_id, exc)
        raise exc


def complete_scan_session(
    db: Session,
    scan_id: str,
    status: str = "completed",
    current_stage: Optional[str] = None,
    progress: Optional[int] = None,
    stats_summary: Optional[Dict[str, Any]] = None,
    execution_logs: Optional[Any] = None,
) -> Optional[ScanSessions]:
    """
    Updates the status of a scan session and sets its completed_at timestamp,
    progress, stage, stats summary, and execution logs.

    :param db: Active SQLAlchemy Session
    :param scan_id: Unique scan identifier
    :param status: Final status ('completed', 'failed', 'stopped', etc.)
    :param current_stage: Name of the current/final stage
    :param progress: Scan completion percentage (0-100)
    :param stats_summary: Dictionary of summary statistics
    :param execution_logs: Structured log messages or status trace
    :return: Updated ScanSessions record or None if not found
    """
    try:
        session = (
            db.query(ScanSessions).filter(ScanSessions.scan_id == scan_id).first()
        )
        if not session:
            logger.warning("ScanSession not found for scan_id: %s", scan_id)
            return None

        now_utc = datetime.now(timezone.utc)
        session.status = status
        session.current_stage = current_stage or status
        if progress is not None:
            session.progress = progress
        elif status in ("completed", "stopped", "failed", "partial"):
            session.progress = 100

        session.completed_at = now_utc

        # Compute or save stats_summary
        if stats_summary:
            session.stats_summary = stats_summary
        else:
            # Dynamically compute summary counts from database tables
            asset_count = db.query(Assets).filter(Assets.scan_id == scan_id).count()
            findings = db.query(VulnerabilityFindings).filter(VulnerabilityFindings.scan_id == scan_id).all()
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in findings:
                sev = (f.severity or "info").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1
                else:
                    severity_counts["info"] += 1
            session.stats_summary = {
                "total_assets": asset_count,
                "total_vulnerabilities": len(findings),
                "severity_counts": severity_counts,
                "completed_at": now_utc.isoformat(),
            }

        if execution_logs is not None:
            session.execution_logs = execution_logs

        db.commit()
        db.refresh(session)
        logger.info("ScanSession %s marked as %s (progress: %d%%)", scan_id, status, session.progress)
        return session

    except Exception as exc:
        db.rollback()
        logger.error("Failed to complete scan_session %s: %s", scan_id, exc)
        raise exc


def save_ai_report(
    db: Session,
    scan_id: str,
    executive_report: Optional[str] = None,
    technical_report: Optional[str] = None,
    model_used: Optional[str] = None,
    report_metadata: Optional[Dict[str, Any]] = None,
) -> AIReports:
    """
    Saves or updates AI-generated reports (executive and/or technical) for a scan session.

    :param db: Active SQLAlchemy Session
    :param scan_id: Unique scan identifier
    :param executive_report: Markdown or plain text executive report
    :param technical_report: Markdown or plain text technical report
    :param model_used: Name of AI model used (e.g. gemini-1.5-flash)
    :param report_metadata: JSON-serializable report metadata dict
    :return: AIReports record
    """
    try:
        report = db.query(AIReports).filter(AIReports.scan_id == scan_id).first()
        if not report:
            report = AIReports(
                scan_id=scan_id,
                executive_report=executive_report,
                technical_report=technical_report,
                model_used=model_used or "gemini-1.5-flash",
                report_metadata=report_metadata,
                created_at=datetime.now(timezone.utc),
            )
            db.add(report)
        else:
            if executive_report is not None:
                report.executive_report = executive_report
            if technical_report is not None:
                report.technical_report = technical_report
            if model_used is not None:
                report.model_used = model_used
            if report_metadata is not None:
                report.report_metadata = report_metadata

        db.commit()
        db.refresh(report)
        logger.info("Successfully saved AI report for scan_id: %s (model: %s)", scan_id, report.model_used)
        return report

    except Exception as exc:
        db.rollback()
        logger.error("Failed to save AI report for scan_id %s: %s", scan_id, exc)
        raise exc


def get_or_set_system_setting(
    db: Session,
    key: str,
    default_value: Optional[str] = None,
    description: Optional[str] = None,
) -> str:
    """
    Retrieves a system setting by key. If absent and default_value is provided,
    creates the record with default_value.

    :param db: Active SQLAlchemy Session
    :param key: Configuration key name
    :param default_value: Optional default value if not set
    :param description: Optional description
    :return: Current string value of the setting
    """
    try:
        setting = db.query(SystemSettings).filter(SystemSettings.key == key).first()
        if not setting:
            if default_value is not None:
                setting = SystemSettings(
                    key=key,
                    value=default_value,
                    description=description,
                    updated_at=datetime.now(timezone.utc),
                )
                db.add(setting)
                db.commit()
                db.refresh(setting)
                return default_value
            return ""
        return setting.value or ""
    except Exception as exc:
        logger.warning("Error getting/setting system_settings '%s': %s", key, exc)
        return default_value or ""


def ingest_scan_from_directory(
    db: Session,
    scan_id: str,
    domain: Optional[str] = None,
    session_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    High-level ingestion pipeline that reads artifact files from a scan directory
    and loads all discovered data (Target, Session, Assets, Vulnerabilities, Reports)
    into the database.

    :param db: Active SQLAlchemy Session
    :param scan_id: Identifier of the scan session
    :param domain: Optional domain name; if not given, read from status.json
    :param session_dir: Directory containing scan files; defaults to scans/<scan_id>
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if not session_dir:
        session_dir = os.path.join(base_dir, "scans", scan_id)

    if not os.path.exists(session_dir):
        raise FileNotFoundError(f"Session directory does not exist: {session_dir}")

    # 1. Read status.json to detect domain and final status
    status_file = os.path.join(session_dir, "status.json")
    status_data: Dict[str, Any] = {}
    if os.path.exists(status_file):
        try:
            with open(status_file, "r", encoding="utf-8") as f:
                status_data = json.load(f)
        except Exception as e:
            logger.warning("Could not read %s: %s", status_file, e)

    target_domain = domain or status_data.get("target_domain") or "unknown-target.local"

    # Accurately resolve status respecting manual stop, failure, partial, or completion
    status_val = status_data.get("status") or ""
    stage = status_data.get("current_stage", "")
    has_err = status_data.get("has_error", False)

    if stage in ("stopped", "cancelled") or status_val in ("stopped", "cancelled"):
        final_status = "stopped"
    elif stage == "failed" or status_val == "failed":
        final_status = "failed"
    elif stage == "partial" or status_val == "partial":
        final_status = "partial"
    elif status_data.get("is_completed") and not has_err:
        final_status = "completed"
    elif has_err:
        final_status = "partial" if (active_urls or api_endpoints) else "failed"
    else:
        final_status = status_val or stage or "completed"

    progress = status_data.get("progress", 100 if final_status in ("completed", "stopped") else 0)
    stats_summary = status_data.get("stats")
    execution_logs = status_data.get("logs")

    # 2. Register Target and ScanSession
    target, session = create_target_and_session(db, target_domain, scan_id)

    # 3. Read and ingest Assets (active_urls.json & api_endpoints.json)
    active_urls: List[Dict[str, Any]] = []
    active_urls_file = os.path.join(session_dir, "active_urls.json")
    if os.path.exists(active_urls_file):
        try:
            with open(active_urls_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    if content.startswith("["):
                        active_urls = json.loads(content)
                    else:
                        for line in content.splitlines():
                            if line.strip():
                                active_urls.append(json.loads(line.strip()))
        except Exception as e:
            logger.warning("Error reading active_urls.json: %s", e)

    api_endpoints: List[Dict[str, Any]] = []
    api_endpoints_file = os.path.join(session_dir, "api_endpoints.json")
    if os.path.exists(api_endpoints_file):
        try:
            with open(api_endpoints_file, "r", encoding="utf-8") as f:
                api_endpoints = json.load(f)
        except Exception as e:
            logger.warning("Error reading api_endpoints.json: %s", e)

    saved_assets = save_discovered_assets(db, scan_id, active_urls, api_endpoints)

    # 4. Read and ingest Vulnerabilities
    vulnerabilities: List[Dict[str, Any]] = []
    unified_file = os.path.join(session_dir, "unified_vulnerabilities.json")
    if not os.path.exists(unified_file):
        unified_file = os.path.join(session_dir, "vulnerabilities.json")

    if os.path.exists(unified_file):
        try:
            with open(unified_file, "r", encoding="utf-8") as f:
                vulnerabilities = json.load(f)
        except Exception as e:
            logger.warning("Error reading vulnerabilities file: %s", e)

    saved_findings = ingest_vulnerabilities(db, scan_id, vulnerabilities)

    # 5. Read and ingest AI Reports (if available)
    exec_md_file = os.path.join(session_dir, "ai_report_executive.md")
    tech_md_file = os.path.join(session_dir, "ai_report_technical.md")
    ai_json_file = os.path.join(session_dir, "ai_report.json")
    exec_report = None
    tech_report = None
    model_used = None
    report_metadata = None

    if os.path.exists(ai_json_file):
        try:
            with open(ai_json_file, "r", encoding="utf-8") as f:
                ai_data = json.load(f)
                model_used = ai_data.get("model_used")
                report_metadata = {
                    "generated_at": ai_data.get("generated_at"),
                    "cached": ai_data.get("cached", False),
                    "execution_time_sec": ai_data.get("execution_time_sec"),
                }
        except Exception:
            pass

    if os.path.exists(exec_md_file):
        try:
            with open(exec_md_file, "r", encoding="utf-8") as f:
                exec_report = f.read()
        except Exception:
            pass

    if os.path.exists(tech_md_file):
        try:
            with open(tech_md_file, "r", encoding="utf-8") as f:
                tech_report = f.read()
        except Exception:
            pass

    if exec_report or tech_report:
        save_ai_report(
            db,
            scan_id,
            executive_report=exec_report,
            technical_report=tech_report,
            model_used=model_used or "gemini-1.5-flash",
            report_metadata=report_metadata,
        )

    # 6. Complete Session
    complete_scan_session(
        db,
        scan_id,
        status=final_status,
        current_stage=stage or final_status,
        progress=progress,
        stats_summary=stats_summary,
        execution_logs=execution_logs,
    )

    return {
        "scan_id": scan_id,
        "target_id": target.id,
        "domain": target.domain_name,
        "assets_count": len(saved_assets),
        "vulnerabilities_count": len(saved_findings),
        "status": final_status,
    }


# ==============================================================================
# Demonstration / Self-Test Routine
# ==============================================================================
if __name__ == "__main__":
    from database import SessionLocal, Base, engine

    print("=" * 60)
    print(" YemenScan - Data Ingestion Service Verification")
    print("=" * 60)

    # Ensure tables exist (useful for testing against in-memory or fresh DB)
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db_session:
        sample_domain = "demo-target.local"
        sample_scan_id = f"scan_demo_{int(datetime.now(timezone.utc).timestamp())}"

        print(f"\n[1] Creating Target & Session for {sample_domain} ({sample_scan_id})...")
        target_obj, session_obj = create_target_and_session(db_session, sample_domain, sample_scan_id)
        print(f"    -> Target ID: {target_obj.id}, Session status: {session_obj.status}")

        print("\n[2] Ingesting Sample Assets (HTTPX & Kiterunner)...")
        sample_active_urls = [
            {
                "url": f"https://{sample_domain}:443",
                "port": "443",
                "title": "Demo Portal",
                "webserver": "nginx/1.24",
                "tech": ["Nginx", "Vue.js", "Express"],
            },
            {
                "url": f"http://{sample_domain}:80",
                "port": "80",
                "title": "Redirect",
                "webserver": "nginx/1.24",
                "tech": ["Nginx"],
            },
        ]
        sample_api_endpoints = [
            {
                "url": f"https://{sample_domain}:443/api/v1/auth/login",
                "path": "/api/v1/auth/login",
                "status_code": 200,
                "content_type": "application/json",
                "is_auth_endpoint": True,
            },
            {
                "url": f"https://{sample_domain}:443/api/v1/users",
                "path": "/api/v1/users",
                "status_code": 401,
                "content_type": "application/json",
            },
        ]
        assets = save_discovered_assets(db_session, sample_scan_id, sample_active_urls, sample_api_endpoints)
        print(f"    -> Ingested {len(assets)} assets.")

        print("\n[3] Ingesting Sample Vulnerabilities (Catalog + Findings)...")
        sample_vulns = [
            {
                "id": "cve-2023-45678",
                "title": "Nginx HTTP/2 Rapid Reset Denial of Service",
                "severity": "HIGH",
                "url": f"https://{sample_domain}:443",
                "description": "Stream cancellation leading to resource exhaustion.",
                "remediation": "Update Nginx to version 1.25.3 or higher.",
                "classification": {
                    "cve-id": "CVE-2023-45678",
                    "cwe-id": "CWE-400",
                    "cvss-score": 7.5,
                    "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    "owasp-top10": "A05:2021-Security Misconfiguration",
                },
                "evidence": "Observed rapid reset frames accepted by server.",
            },
            {
                "id": "WAP-CORS-WILDCARD",
                "title": "Overly Permissive CORS Access-Control-Allow-Origin",
                "severity": "MEDIUM",
                "category": "OWASP A01:2021-Broken Access Control",
                "url": f"https://{sample_domain}:443/api/v1/users",
                "description": "Access-Control-Allow-Origin header is set to wildcard (*).",
                "remediation": "Restrict CORS origin headers to trusted domains.",
                "evidence": "Access-Control-Allow-Origin: *",
            },
        ]
        findings = ingest_vulnerabilities(db_session, sample_scan_id, sample_vulns)
        print(f"    -> Ingested {len(findings)} findings.")

        print("\n[4] Completing Scan Session...")
        completed_session = complete_scan_session(db_session, sample_scan_id, status="completed")
        print(f"    -> Session {completed_session.scan_id} marked as '{completed_session.status}' at {completed_session.completed_at}")

        print("\n[+] Verification completed successfully!\n")
