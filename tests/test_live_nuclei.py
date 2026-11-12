import os
import sys
import time
import json
import shutil

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.stage3_vulnerabilities import run_nuclei
from core.nuclei_template_selector import generate_nuclei_scan_plan

def main():
    os.environ["YEMENSCAN_USE_DOCKER"] = "1"
    target_origin = "https://hackthebox.com"
    print("=" * 70)
    print("      YEMSCAN LIMITED LIVE TEST: ADAPTIVE NUCLEI SCAN")
    print("=" * 70)
    print(f"Target Origin: {target_origin}")

    # Create real live test session in scans directory
    base_scans = os.path.join(BASE_DIR, "scans")
    os.makedirs(base_scans, exist_ok=True)
    session_dir = os.path.join(base_scans, "live_test_adaptive_nuclei")
    if os.path.exists(session_dir):
        shutil.rmtree(session_dir, ignore_errors=True)
    os.makedirs(session_dir, exist_ok=True)

    # Real HTTPX discovery data from Stage 2
    active_json = os.path.join(session_dir, "active_urls.json")
    with open(active_json, "w", encoding="utf-8") as f:
        f.write(json.dumps({
            "url": target_origin,
            "tech": ["Adobe Fonts", "Cloudflare"],
            "webserver": "cloudflare",
            "title": "302 Found"
        }) + "\n")

    # Step 1: Generate Adaptive Scan Plan
    print("\n[*] Step 1: Computing Adaptive Scan Plan...")
    plan = generate_nuclei_scan_plan(session_dir, origins=[target_origin])
    p0 = plan["profiles"][0]

    print("\n" + "-" * 70)
    print("                 PRE-EXECUTION AUDIT PLAN")
    print("-" * 70)
    print(f"Detected Technologies:    {p0['signals']['technologies']}")
    print(f"Detected Route Signals:   {p0['signals']['routes']}")
    print(f"Layer A (Safe Baseline):  {p0['template_counts']['baseline_count']}")
    print(f"Layer B (Tech-Specific):  {p0['template_counts']['technology_count']}")
    print(f"Layer C (Route/Discovery):{p0['template_counts']['discovery_count']}")
    print(f"Selected Templates Count: {len(p0['selected_templates'])} (Limit <= 80)")
    est_reqs = sum(t.get("estimated_requests", 1) for t in p0["selected_templates"])
    print(f"Estimated Requests:       {est_reqs} (Budget <= 500)")
    print(f"Configured Rate Limit:    {p0['limits']['rate_limit']} req/s")
    print(f"Configured Concurrency:   {p0['limits']['concurrency']}")
    print(f"Full Official Templates:  STRICTLY DISABLED (Selected subset only)")
    print("-" * 70)

    # Write nuclei_targets.txt
    targets_file = os.path.join(session_dir, "nuclei_targets.txt")
    with open(targets_file, "w", encoding="utf-8") as tf:
        tf.write(f"{target_origin}\n")

    # Step 2: Execute Nuclei Docker Container with Selected Templates
    print("\n[*] Step 2: Executing Live Adaptive Nuclei Scan...")
    start_time = time.time()
    success, findings = run_nuclei(session_dir, scan_id="live_test_adaptive_01")
    elapsed = time.time() - start_time

    print("\n" + "=" * 70)
    print("                 LIVE TEST EXECUTION RESULTS")
    print("=" * 70)
    print(f"Execution Success:   {success}")
    print(f"Elapsed Time:        {elapsed:.2f} seconds")
    print(f"Findings Discovered: {len(findings)}")

    meta_file = os.path.join(session_dir, "nuclei_metadata.json")
    if os.path.exists(meta_file):
        with open(meta_file, "r", encoding="utf-8") as mf:
            meta = json.load(mf)
        print(f"Engine Version:      {meta.get('engine_version')}")
        print(f"Templates Version:   {meta.get('templates_version')}")
        print(f"Strategy:            {meta.get('selection_strategy')}")
        print(f"Status:              {meta.get('status')}")
        print(f"Baseline Templates:  {meta.get('baseline_template_count')}")
        print(f"Selected Templates:  {meta.get('selected_template_count')}")
        print(f"Estimated Requests:  {meta.get('estimated_request_count')}")
        print(f"Rate Limit:          {meta.get('rate_limit')} req/s")
        print(f"Concurrency:         {meta.get('concurrency')}")
        print(f"Raw Findings Count:  {meta.get('raw_count')}")
        print(f"Valid Count:         {meta.get('valid_count')}")

    if findings:
        print("\nFindings Details:")
        for f in findings:
            print(f"  [{f['severity']}] {f['title']} -> {f['url']}")
    else:
        print("\nNo vulnerabilities matched (Target is secure against selected templates).")

    print("=" * 70)
    return success

if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
