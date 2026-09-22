"""Offline threat-intelligence cache. Runtime never requires Internet access."""
from __future__ import annotations
import ipaddress, json
from pathlib import Path

class ThreatIntelCache:
    def __init__(self, path="threat_intel_cache.json"):
        self.path=Path(path)
        self.data={"ips":{}, "domains":{}, "hashes":{}}
        if self.path.exists():
            self.data=json.loads(self.path.read_text(encoding="utf-8"))
    def lookup_ip(self, value: str) -> dict:
        ip=str(ipaddress.ip_address(value))
        return self.data["ips"].get(ip, {})
    def put_ip(self, value: str, metadata: dict) -> None:
        ip=str(ipaddress.ip_address(value))
        self.data["ips"][ip]=dict(metadata)
        self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
