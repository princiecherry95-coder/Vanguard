# Vanguard-SIEM Problem Statement

## Purpose
Vanguard-SIEM is an offline-first Security Information and Event Management platform for isolated and mission-critical environments.

## Problem
Security telemetry is heterogeneous, distributed, noisy, and difficult to correlate manually. In air-gapped environments, cloud SIEM platforms, external threat intelligence, and cloud AI services may be unavailable or inappropriate. This can delay detection, increase alert fatigue, and make incident evidence difficult to explain and preserve.

## Solution
Vanguard-SIEM locally ingests, validates, sanitizes, normalizes, detects, correlates, prioritizes, and presents security events without requiring cloud runtime dependencies.

## Security objectives
- Confidentiality of credentials and sensitive telemetry.
- Integrity and provenance of security evidence.
- Availability of local detection and analysis.
- Explainable and auditable detection decisions.
- Safe handling of untrusted log input.
- Human analyst control over incident decisions.

## Scope
Supported telemetry includes Syslog/Linux authentication, Windows event exports, web logs, firewall telemetry, network-security datasets, and controlled CSV/JSON/JSONL/text evidence.

## Core principle
Untrusted telemetry is data, never executable instructions.
