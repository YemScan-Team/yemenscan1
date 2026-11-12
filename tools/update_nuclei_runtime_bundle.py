import os
import sys
import json
import shutil
import hashlib
from typing import Dict, List, Set, Any, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.nuclei_template_selector import (
    UNIVERSAL_SAFE_BASELINE_PATHS,
    TECH_TAXONOMY,
    ELIGIBLE_CATEGORIES,
    SafeManifestManager,
    classify_template_content
)

# Capabilities explicitly owned by Wapiti to prune from Nuclei runtime
WAPITI_OWNED_TAGS: Set[str] = {
    "headers", "security-headers", "cookie", "httponly", 
    "samesite", "csp", "clickjacking", "x-frame-options", "cors"
}
WAPITI_OWNED_KEYWORDS: List[str] = [
    "x-content-type-options", "strict-transport-security", 
    "content-security-policy", "cookie-flags", "missing-header",
    "http-missing-headers"
]

def compute_file_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def get_dir_size_bytes(directory: str) -> int:
    total_size = 0
    for root, _, files in os.walk(directory):
        for f in files:
            fp = os.path.join(root, f)
            total_size += os.path.getsize(fp)
    return total_size

def determine_coverage_family(tpl_id: str, rel_path: str, tags: List[str]) -> str:
    tid_low = tpl_id.lower()
    rel_low = rel_path.lower()
    if tid_low.startswith("cve-") or tid_low.startswith("cnvd-"):
        return "known_cve_signature"
    if "exposures/configs" in rel_low or "env" in tid_low:
        return "exposed_configuration"
    if "exposed-panels" in rel_low or "login-check" in rel_low:
        return "exposed_panels"
    if "backup" in rel_low:
        return "backup_file_discovery"
    if any(t in ["tech", "version", "detect"] for t in tags):
        return "technology_version_check"
    if any(cat in rel_low for cat in ["cves", "vulnerabilities"]):
        return "product_specific_vulnerability"
    return "safe_signature_based_checks"

def build_runtime_bundle(
    official_dir: str = os.path.join(BASE_DIR, "nuclei_templates_official"),
    runtime_dir: str = os.path.join(BASE_DIR, "nuclei_runtime_templates"),
    manifest_output_path: str = os.path.join(BASE_DIR, "nuclei_runtime_manifest.json")
) -> Dict[str, Any]:
    print("=" * 75)
    print("      YEMENSCAN NUCLEI RUNTIME TEMPLATE PRUNER & BUNDLE BUILDER")
    print("=" * 75)

    if not os.path.exists(official_dir):
        raise FileNotFoundError(f"Official templates directory not found: {official_dir}")

    # 1. Audit and Load Safe Manifest
    print("[*] Step 1: Loading verified Safe Manifest...")
    mgr = SafeManifestManager(official_dir)
    safe_manifest = mgr.build_or_load_manifest()
    stats = mgr.get_stats()

    total_audited = stats.get("total_categorized", 11719)
    safe_total = stats.get("safe_count", len(safe_manifest))
    review_total = stats.get("review_count", 4642)
    blocked_total = stats.get("blocked_count", 731)

    print(f"  Total Audited: {total_audited}")
    print(f"  Safe Total:    {safe_total}")
    print(f"  Review Total:  {review_total} (Excluded)")
    print(f"  Blocked Total: {blocked_total} (Excluded)")

    # 2. Reachability & Ownership Analysis
    print("\n[*] Step 2: Executing Reachability & Capability Ownership Filtering...")
    reachable_candidates: Dict[str, Dict[str, Any]] = {}
    selection_sources: Dict[str, Set[str]] = {}
    removed_wapiti_overlap_count = 0

    # A. Baseline reachability
    for bp in UNIVERSAL_SAFE_BASELINE_PATHS:
        for tpl in safe_manifest.values():
            if tpl["relative_path"].lower() == bp.lower():
                tid = tpl["template_id"]
                tags = set(tpl.get("tags", []))
                rel_p = tpl["relative_path"].lower()

                # Filter out Wapiti-owned generic checks
                if (tags & WAPITI_OWNED_TAGS) or any(kw in rel_p for kw in WAPITI_OWNED_KEYWORDS):
                    removed_wapiti_overlap_count += 1
                    continue

                reachable_candidates[tid] = tpl
                selection_sources.setdefault(tid, set()).add("baseline")
                break

    # B. Technology reachability
    eligible_tech_names = {k.lower() for k, cat in TECH_TAXONOMY.items() if cat in ELIGIBLE_CATEGORIES}
    for tid, tpl in safe_manifest.items():
        tags = set(tpl.get("tags", []))
        rel_p = tpl["relative_path"].lower()

        # Filter out Wapiti-owned generic checks
        if (tags & WAPITI_OWNED_TAGS) or any(kw in rel_p for kw in WAPITI_OWNED_KEYWORDS):
            removed_wapiti_overlap_count += 1
            continue

        matched_tech = False
        for t_name in eligible_tech_names:
            if t_name in rel_p.split("/") or t_name in rel_p:
                matched_tech = True
                break
            elif any(t_name == t or t_name in t for t in tags):
                matched_tech = True
                break

        if matched_tech:
            reachable_candidates[tid] = tpl
            selection_sources.setdefault(tid, set()).add("technology")

    # C. Discovery reachability
    discovery_routes = ["swagger", "openapi", "graphql", "actuator", "wordpress"]
    for tid, tpl in safe_manifest.items():
        tags = set(tpl.get("tags", []))
        rel_p = tpl["relative_path"].lower()

        if (tags & WAPITI_OWNED_TAGS) or any(kw in rel_p for kw in WAPITI_OWNED_KEYWORDS):
            continue

        matched_route = False
        for r in discovery_routes:
            if r in rel_p or any(r in t for t in tags):
                matched_route = True
                break

        if matched_route:
            reachable_candidates[tid] = tpl
            selection_sources.setdefault(tid, set()).add("discovery")

    runtime_template_count = len(reachable_candidates)
    unreachable_safe_count = safe_total - runtime_template_count
    total_removed_count = total_audited - runtime_template_count

    print(f"  Reachable Safe Templates Selected: {runtime_template_count}")
    print(f"  Unreachable Safe Templates Pruned: {unreachable_safe_count}")
    print(f"  Wapiti-Owned Overlap Pruned:       {removed_wapiti_overlap_count}")
    print(f"  Total Unused Templates Removed:    {total_removed_count} ({total_removed_count / total_audited:.1%})")

    # 3. Create Clean Runtime Bundle Directory
    print("\n[*] Step 3: Populating nuclei_runtime_templates/...")
    if os.path.exists(runtime_dir):
        shutil.rmtree(runtime_dir)
    os.makedirs(runtime_dir, exist_ok=True)

    template_records = []
    bundle_hashes = []

    for tid, tpl in sorted(reachable_candidates.items()):
        rel_p = tpl["relative_path"]
        src_path = os.path.join(official_dir, rel_p)
        dest_path = os.path.join(runtime_dir, rel_p)

        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        shutil.copy2(src_path, dest_path)

        file_sha256 = compute_file_sha256(dest_path)
        bundle_hashes.append(file_sha256)

        family = determine_coverage_family(tid, rel_p, tpl.get("tags", []))
        sources = sorted(list(selection_sources.get(tid, ["safe_manifest"])))

        template_records.append({
            "id": tid,
            "source_path": rel_p.replace("\\", "/"),
            "sha256": file_sha256,
            "severity": tpl.get("severity", "INFO"),
            "request_cost": tpl.get("request_cost", 1),
            "coverage_family": family,
            "selection_sources": sources
        })

    # Combined bundle hash
    combined_hash = hashlib.sha256("".join(bundle_hashes).encode("utf-8")).hexdigest()

    # 4. Compute directory sizes
    official_size = get_dir_size_bytes(official_dir)
    runtime_size = get_dir_size_bytes(runtime_dir)
    size_reduction_pct = (1.0 - (runtime_size / official_size)) * 100.0 if official_size > 0 else 0.0

    print(f"  Official Folder Size: {official_size / (1024*1024):.2f} MB")
    print(f"  Runtime Bundle Size:  {runtime_size / (1024*1024):.2f} MB")
    print(f"  Disk Space Reduction: {size_reduction_pct:.1f}%")

    # 5. Write nuclei_runtime_manifest.json
    manifest_data = {
        "upstream_version": "v10.5.1",
        "upstream_commit": "79fb682760ab3d5b0e22afbb44709353cbebf023",
        "audited_total": total_audited,
        "safe_total": safe_total,
        "runtime_template_count": runtime_template_count,
        "removed_review_count": review_total,
        "removed_blocked_count": blocked_total,
        "removed_unreachable_safe_count": unreachable_safe_count,
        "removed_wapiti_overlap_count": removed_wapiti_overlap_count,
        "total_pruned_from_upstream": total_removed_count,
        "runtime_bundle_sha256": combined_hash,
        "official_size_bytes": official_size,
        "runtime_size_bytes": runtime_size,
        "size_reduction_percentage": round(size_reduction_pct, 2),
        "templates": template_records
    }

    with open(manifest_output_path, "w", encoding="utf-8") as jf:
        json.dump(manifest_data, jf, ensure_ascii=False, indent=2)

    # Also write sorted text file of runtime IDs
    txt_output_path = os.path.splitext(manifest_output_path)[0] + ".txt"
    with open(txt_output_path, "w", encoding="utf-8") as tf:
        for t in template_records:
            tf.write(f"{t['id']}\n")

    print(f"[+] Runtime Manifest successfully created: {manifest_output_path}")
    print(f"[+] Runtime IDs list saved to: {txt_output_path}")
    print("=" * 75)

    return manifest_data

if __name__ == "__main__":
    build_runtime_bundle()
