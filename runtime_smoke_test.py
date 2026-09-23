"""Cross-platform local runtime smoke test for Vanguard-SIEM."""
from __future__ import annotations
import os, subprocess, sys, time, urllib.request

MODULES = ("engine","ingestion","audit","distributed","firewall","remediation","threat_intel","windows_events","local_ai","soc_pipeline")

def main() -> None:
    for name in MODULES:
        __import__(name)
    from soc_pipeline import analyze_bytes
    sample = (
        b"2026-09-23T10:00:00+00:00 sshd: Failed password for user=admin from 10.10.1.7\n"
        b"2026-09-23T10:00:10+00:00 10.10.1.7 GET /search?q=' OR '1'='1' HTTP/1.1\n"
    )
    result = analyze_bytes(sample, "runtime-smoke.log", "TEXT")
    assert result["records"] == 2
    assert len(result["sha256"]) == 64
    assert result["analysis"]["alerts"]
    env = dict(os.environ)
    env["STREAMLIT_BROWSER_GATHER_USAGE_STATS"] = "false"
    proc = subprocess.Popen(
        [sys.executable,"-m","streamlit","run","app.py","--server.headless","true","--server.port","8501"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            if proc.poll() is not None:
                output = proc.stdout.read() if proc.stdout else ""
                raise RuntimeError(f"Streamlit exited early with code {proc.returncode}: {output[-4000:]}")
            try:
                with urllib.request.urlopen("http://127.0.0.1:8501/_stcore/health", timeout=2) as response:
                    body = response.read().decode("utf-8", errors="replace")
                    if response.status == 200 and "ok" in body.lower():
                        print(f"Vanguard-SIEM local runtime smoke test: PASS ({sys.platform})")
                        return
            except Exception:
                time.sleep(1)
        output = proc.stdout.read() if proc.stdout else ""
        raise RuntimeError(f"Streamlit health check timed out. Output: {output[-4000:]}")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait(timeout=5)

if __name__ == "__main__":
    main()
