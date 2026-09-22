"""Human-in-the-loop remediation playbooks."""
from __future__ import annotations
from firewall import block_ip

def propose(alert: dict) -> dict:
    ip = alert.get("source_ip")
    action = "BLOCK_SOURCE_IP" if ip else "COLLECT_MORE_EVIDENCE"
    return {"requires_approval": True, "action": action, "source_ip": ip, "reason": alert.get("description","")}

def execute_approved(playbook: dict) -> dict:
    if not playbook.get("approved"):
        return {"status":"APPROVAL_REQUIRED"}
    if playbook.get("action") == "BLOCK_SOURCE_IP":
        return block_ip(playbook["source_ip"], apply=True)
    return {"status":"NO_AUTOMATED_ACTION"}
