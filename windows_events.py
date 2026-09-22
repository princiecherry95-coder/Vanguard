"""Optional Windows Event Log collector. Safe no-op on non-Windows hosts."""
from __future__ import annotations
import platform, subprocess

def available() -> bool:
    return platform.system() == "Windows"

def collect(channel: str = "Security", max_events: int = 100) -> list[str]:
    if not available():
        return []
    safe_channel = channel.replace("'","''")
    script = f"Get-WinEvent -LogName '{safe_channel}' -MaxEvents {int(max_events)} | ForEach-Object {{ $_.ToXml() }}"
    result = subprocess.run(["powershell","-NoProfile","-NonInteractive","-Command",script],capture_output=True,text=True,check=False)
    if result.returncode:
        raise RuntimeError(result.stderr[:1000])
    return [x for x in result.stdout.splitlines() if x.strip()]
