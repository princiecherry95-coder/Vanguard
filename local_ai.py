"""Optional local AI adapter. Offline by default; no cloud API calls."""
from __future__ import annotations
import json, os, urllib.request

DEFAULT_MODEL = os.environ.get("VANGUARD_LOCAL_MODEL", "llama3")
OLLAMA_URL = os.environ.get("VANGUARD_OLLAMA_URL", "http://127.0.0.1:11434/api/generate")

def explain(alert_text: str) -> str:
    if os.environ.get("VANGUARD_LOCAL_AI", "0") != "1":
        return "Deterministic local guidance active; local model inference is disabled."
    payload = json.dumps({"model": DEFAULT_MODEL, "prompt": alert_text, "stream": False}).encode()
    request = urllib.request.Request(OLLAMA_URL, data=payload, headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        data = json.loads(response.read().decode())
    return str(data.get("response", ""))[:4096]
