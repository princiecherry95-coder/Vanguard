"""Defensive local firewall adapter with explicit human approval."""
from __future__ import annotations
import ipaddress, platform, subprocess

def validate_ip(value: str) -> str:
    return str(ipaddress.ip_address(value))

def block_ip(ip: str, rule_name: str = "Vanguard-SIEM-Quarantine", apply: bool = False) -> dict:
    ip = validate_ip(ip)
    if not apply:
        return {"status":"DRY_RUN","ip":ip,"rule":rule_name}
    if platform.system() != "Windows":
        return {"status":"UNSUPPORTED_PLATFORM","ip":ip,"rule":rule_name}
    cmd=["netsh","advfirewall","firewall","add","rule",f"name={rule_name}", "dir=in","action=block",f"remoteip={ip}"]
    completed=subprocess.run(cmd, capture_output=True, text=True, check=False)
    return {"status":"APPLIED" if completed.returncode==0 else "FAILED","ip":ip,"rule":rule_name,"returncode":completed.returncode,"stderr":completed.stderr[:1000]}
