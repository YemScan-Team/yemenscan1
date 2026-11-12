import os
import sys
import json

# UTF-8 encoding configuration
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.stage2_web_probing import run_kiterunner_or_api_probing

def run_live_test():
    session_dir = os.path.join(BASE_DIR, "output", "live_kiterunner_test")
    os.makedirs(session_dir, exist_ok=True)
    target_url = "https://academy.hackthebox.com"
    test_wordlist = os.path.join(BASE_DIR, "tests", "fixtures", "routes-test.kite")

    print(f"[*] Starting limited live test against {target_url}...")
    success, candidates = run_kiterunner_or_api_probing(
        active_urls=[target_url],
        session_dir=session_dir,
        scan_id="live_kr_test",
        custom_wordlist=test_wordlist
    )

    print(f"[+] Scan finished: success={success}, candidates={len(candidates)}")

    files = [
        "kiterunner_input.txt",
        "kiterunner_raw.jsonl",
        "kiterunner_stderr.log",
        "api_endpoints.json",
        "api_endpoints.txt",
        "kiterunner_metadata.json"
    ]

    for f in files:
        fpath = os.path.join(session_dir, f)
        exists = os.path.exists(fpath)
        size = os.path.getsize(fpath) if exists else 0
        print(f"    - {f}: exists={exists}, size={size} bytes")

    meta_path = os.path.join(session_dir, "kiterunner_metadata.json")
    if os.path.exists(meta_path):
        with open(meta_path, "r", encoding="utf-8") as mf:
            meta = json.load(mf)
            print("[+] Live Metadata Summary:")
            print(json.dumps(meta, indent=2))

    raw_path = os.path.join(session_dir, "kiterunner_raw.jsonl")
    if os.path.exists(raw_path):
        with open(raw_path, "r", encoding="utf-8") as rf:
            raw_lines = rf.readlines()
            print(f"[+] Raw JSONL lines count: {len(raw_lines)}")
            for l in raw_lines[:5]:
                print(f"    raw line: {l.strip()}")

    endpoints_json_path = os.path.join(session_dir, "api_endpoints.json")
    if os.path.exists(endpoints_json_path):
        with open(endpoints_json_path, "r", encoding="utf-8") as ej:
            endpoints = json.load(ej)
            print(f"[+] Candidate endpoints in api_endpoints.json: {len(endpoints)}")
            for ep in endpoints:
                print(f"    - {ep.get('method')} {ep.get('url')} [{ep.get('status_code')}]")

if __name__ == "__main__":
    run_live_test()
