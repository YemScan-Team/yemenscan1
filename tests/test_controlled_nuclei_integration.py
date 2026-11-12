import os
import sys
import json
import time

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.runner import run_docker_tool
from core.stage3_vulnerabilities import (
    prepare_nuclei_targets,
    parse_nuclei_json_output,
    write_nuclei_template_manifest,
    clean_nuclei_session_artifacts,
    NUCLEI_DOCKER_IMAGE,
    NUCLEI_ENGINE_VERSION,
    NUCLEI_ENGINE_DIGEST,
    NUCLEI_TEMPLATES_OFFICIAL_DIR,
    NUCLEI_TEMPLATES_VERSION,
    NUCLEI_TEMPLATES_COMMIT,
    NUCLEI_TEMPLATES_CHECKSUM,
)


def main():
    print("=" * 70)
    print("   YEMENSCAN NUCLEI CONTROLLED DOCKER INTEGRATION TEST")
    print("=" * 70)

    session_dir = os.path.abspath("output/test_controlled_nuclei")
    os.makedirs(session_dir, exist_ok=True)
    clean_nuclei_session_artifacts(session_dir)

    target_origin = "https://academy.hackthebox.com"
    active_urls_file = os.path.join(session_dir, "active_urls.txt")
    with open(active_urls_file, "w", encoding="utf-8") as f:
        f.write(f"{target_origin}\n")

    # 1. Prepare Targets
    targets = prepare_nuclei_targets(session_dir)
    print(f"[+] Step 1: Targets Prepared: {targets}")
    assert targets == [target_origin]

    manifest = write_nuclei_template_manifest(session_dir)
    print(f"[+] Step 2: Manifest Generated: {manifest['templates_version']} | signature={manifest['signature_verification']}")

    # 2. Execute Real Docker with official signed templates and -dut
    # Using official signed CVE template for rapid deterministic verification
    print("\n[*] Step 3: Running Real Docker Nuclei with signed templates & -dut...")
    args = [
        "-l", "/data/nuclei_targets.txt",
        "-t", "/opt/nuclei-templates/http/cves/2021/CVE-2021-26084.yaml",
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
    extra_vols = [(NUCLEI_TEMPLATES_OFFICIAL_DIR, "/opt/nuclei-templates")]

    start_time = time.time()
    success, output = run_docker_tool(
        image=NUCLEI_DOCKER_IMAGE,
        args=args,
        volume_dir=session_dir,
        timeout=180,
        extra_volumes=extra_vols,
        scan_id="test_controlled_nuclei"
    )
    elapsed = time.time() - start_time
    print(f"[+] Docker execution finished in {elapsed:.2f}s | Success={success}")

    assert success is True, f"Docker execution failed: {output}"

    # 3. Verify Raw Output & Invariants (Zero Findings Case)
    raw_file = os.path.join(session_dir, "nuclei_raw.jsonl")
    assert os.path.exists(raw_file), "nuclei_raw.jsonl must exist"

    findings, counts = parse_nuclei_json_output(raw_file, valid_target_origins=set(targets))
    print(f"[+] Step 4: Parsed Real Output -> {len(findings)} findings, raw={counts['raw_count']}")
    assert counts["raw_count"] == 0, "Hardened server should yield 0 findings"
    assert len(findings) == 0, "No fake findings allowed"

    # 4. Verify Controlled Synthetic Test with CVE Classification, Invariants & Provenance
    print("\n[*] Step 5: Injecting controlled test records to verify classification, provenance & invariants...")
    test_raw_file = os.path.join(session_dir, "controlled_raw.jsonl")
    records = [
        # In-scope genuine CVE with full classification
        {
            "template-id": "cve-2021-26084",
            "info": {
                "name": "Confluence Server OGNL Injection",
                "severity": "critical",
                "description": "An OGNL injection flaw exists in Confluence Server.",
                "remediation": "Upgrade to latest secure version.",
                "tags": ["cve", "confluence", "rce"],
                "classification": {
                    "cve-id": ["CVE-2021-26084"],
                    "cwe-id": ["CWE-94"],
                    "cvss-score": 9.8,
                    "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            },
            "matcher-name": "body-match",
            "matched-at": f"{target_origin}/pages/createpage.action"
        },
        # Duplicate of the first
        {
            "template-id": "cve-2021-26084",
            "info": {
                "name": "Confluence Server OGNL Injection",
                "severity": "critical",
                "classification": {
                    "cve-id": ["CVE-2021-26084"],
                    "cwe-id": ["CWE-94"],
                    "cvss-score": 9.8,
                    "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            },
            "matcher-name": "body-match",
            "matched-at": f"{target_origin}/pages/createpage.action"
        },
        # Out of scope finding (attacker origin)
        {
            "template-id": "cve-2021-26084",
            "info": {
                "name": "Out of scope finding",
                "severity": "high",
                "classification": {"cve-id": ["CVE-2021-26084"]}
            },
            "matched-at": "https://external-unauthorized.com/exploit"
        },
        # Template without classification (must have cve_id=None, no hallucination)
        {
            "template-id": "cve-2021-99999-no-classif",
            "info": {
                "name": "Exposure without classification",
                "severity": "medium",
                "tags": ["cve"]
            },
            "matched-at": f"{target_origin}/status"
        },
        # Malformed JSON line
        "{ corrupt invalid json string ",
        # Missing required template-id
        {"info": {"name": "missing template-id"}, "matched-at": target_origin}
    ]

    with open(test_raw_file, "w", encoding="utf-8") as f:
        for r in records:
            if isinstance(r, dict):
                f.write(json.dumps(r) + "\n")
            else:
                f.write(str(r) + "\n")

    ctrl_findings, ctrl_counts = parse_nuclei_json_output(test_raw_file, valid_target_origins=set(targets))

    print(f"\n[+] Step 6: Controlled Records Verification:")
    print(f"    Raw Count:          {ctrl_counts['raw_count']}")
    print(f"    Valid Count:        {ctrl_counts['valid_count']}")
    print(f"    Duplicate Count:    {ctrl_counts['duplicate_count']}")
    print(f"    Out of Scope Count: {ctrl_counts['out_of_scope_count']}")
    print(f"    Invalid Count:      {ctrl_counts['invalid_count']}")

    assert ctrl_counts["raw_count"] == 6
    assert ctrl_counts["valid_count"] == 2
    assert ctrl_counts["duplicate_count"] == 1
    assert ctrl_counts["out_of_scope_count"] == 1
    assert ctrl_counts["invalid_count"] == 2

    # Invariant check
    invariant_sum = ctrl_counts["valid_count"] + ctrl_counts["invalid_count"] + ctrl_counts["duplicate_count"] + ctrl_counts["out_of_scope_count"]
    assert ctrl_counts["raw_count"] == invariant_sum

    # Provenance and classification truth
    f_cve = ctrl_findings[0]
    assert f_cve["cve_id"] == "CVE-2021-26084"
    assert f_cve["cwe_id"] == "CWE-94"
    assert f_cve["cvss_score"] == 9.8
    assert f_cve["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert f_cve["finding_status"] == "scanner_match"
    assert f_cve["source"] == "nuclei"
    assert f_cve["template_signed"] is True

    f_noclass = ctrl_findings[1]
    assert f_noclass["cve_id"] is None, "Must not hallucinate CVE ID from template name"
    assert f_noclass["cwe_id"] is None
    assert f_noclass["cvss_score"] is None

    print("\n" + "=" * 70)
    print("      ALL CONTROLLED INTEGRATION CHECKS PASSED PERFECTLY!")
    print("=" * 70)


if __name__ == "__main__":
    main()
