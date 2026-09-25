"""Versioned, explainable Vanguard detection metadata.

The engine remains deterministic; this registry supplies analyst-facing
metadata without changing the underlying detection decision.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    version: str
    title: str
    severity: str
    confidence: str
    category: str
    mitre_technique: str | None
    analyst_guidance: str


_RULES = {
    "SQL_INJECTION": DetectionRule("SQL_INJECTION", "1.0", "SQL injection indicator", "CRITICAL", "HIGH", "WEB_ATTACK", "T1190", "Validate the request, affected endpoint and application authorization boundary."),
    "XSS": DetectionRule("XSS", "1.0", "Cross-site scripting indicator", "HIGH", "HIGH", "WEB_ATTACK", "T1189", "Inspect the affected parameter and confirm output encoding and input validation."),
    "PATH_MANIPULATION": DetectionRule("PATH_MANIPULATION", "1.0", "Path traversal indicator", "HIGH", "HIGH", "WEB_ATTACK", "T1190", "Review filesystem access and canonicalize/authorize the requested path."),
    "SUSPICIOUS_UPLOAD": DetectionRule("SUSPICIOUS_UPLOAD", "1.0", "Suspicious file upload", "HIGH", "MEDIUM", "WEB_ATTACK", "T1190", "Validate upload type, storage location and execution controls."),
    "COMMAND_INJECTION": DetectionRule("COMMAND_INJECTION", "1.0", "Command injection indicator", "CRITICAL", "HIGH", "EXECUTION", "T1059", "Inspect the parameter and verify that shell execution is not reachable from untrusted input."),
    "SSRF_INDICATOR": DetectionRule("SSRF_INDICATOR", "1.0", "Server-side request forgery indicator", "HIGH", "HIGH", "WEB_ATTACK", "T1190", "Review outbound request controls and metadata/internal address access."),
    "ENCODED_ATTACK": DetectionRule("ENCODED_ATTACK", "1.0", "Repeated encoded attack marker", "MEDIUM", "MEDIUM", "WEB_ATTACK", "T1027", "Decode the relevant parameter and correlate with the destination service."),
    "AUTH_FAILURE": DetectionRule("AUTH_FAILURE", "1.0", "Authentication failure", "MEDIUM", "HIGH", "AUTHENTICATION", "T1110", "Correlate repeated failures by source, account and time window."),
    "PRIVILEGE_ESCALATION": DetectionRule("PRIVILEGE_ESCALATION", "1.0", "Privilege escalation indicator", "HIGH", "MEDIUM", "PRIVILEGE", "T1068", "Verify the account, parent process and authorization change."),
    "BRUTE_FORCE_AUTH": DetectionRule("BRUTE_FORCE_AUTH", "1.0", "Brute-force authentication pattern", "HIGH", "HIGH", "BEHAVIOR", "T1110", "Investigate source, target account and authentication timeline."),
    "DISTRIBUTED_BRUTE_FORCE": DetectionRule("DISTRIBUTED_BRUTE_FORCE", "1.0", "Distributed brute-force pattern", "HIGH", "HIGH", "BEHAVIOR", "T1110", "Correlate all sources and affected accounts before containment."),
    "LATERAL_SCAN": DetectionRule("LATERAL_SCAN", "1.0", "Suspicious network scanning pattern", "HIGH", "MEDIUM", "DISCOVERY", "T1046", "Review destination set, service ports and whether the source is an approved scanner."),
    "SURICATA_ALERT": DetectionRule("SURICATA_ALERT", "1.0", "Suricata signature match", "MEDIUM", "HIGH", "NETWORK_DETECTION", None, "Review the Suricata signature, category, action and related flow evidence."),
}


def get_rule(rule_id: str) -> DetectionRule:
    return _RULES.get(
        rule_id,
        DetectionRule(rule_id, "1.0", rule_id.replace("_", " ").title(), "MEDIUM", "MEDIUM", "OTHER", None, "Review the matched evidence and surrounding timeline."),
    )


def all_rules() -> tuple[DetectionRule, ...]:
    return tuple(_RULES.values())
