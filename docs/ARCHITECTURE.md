# Vanguard-SIEM Architecture

## High-level flow

Security Sources -> Log Ingestion -> Validation -> Sanitization -> Parsing/Normalization -> Detection -> Behavioral Analysis -> Correlation -> Risk/Severity -> SOC Dashboard

## Components

| Component | Responsibility |
|---|---|
| Log Ingestion Center | Controlled local evidence intake |
| Validation Layer | Size, format, encoding and structure checks |
| Sanitization Layer | Credential/token protection and control-character handling |
| Parser/Normalizer | Common event representation |
| Detection Engine | Transparent deterministic rules |
| Behavioral Engine | Multi-event brute-force and scanning detection |
| Correlation Engine | Groups related alerts into incidents |
| Evidence Layer | SHA-256 provenance |
| SOC Dashboard | Analyst presentation |
| Audit Layer | Security-relevant activity records |
| CI/CD | Regression and runtime validation |

## Trust boundaries

1. Untrusted telemetry enters through controlled ingestion.
2. Validation and sanitization form the first trust boundary.
3. Only normalized events reach detection and correlation.
4. Analyst actions remain subject to authorization and audit controls.

## Air-gap design
Runtime detection is local and deterministic. Vanguard does not require cloud LLMs, external threat-intelligence APIs, or Internet access to analyze supplied telemetry.

## Defense in depth
Network isolation, authentication, input validation, sanitization, safe parsing, deterministic detection, behavioral analysis, correlation, evidence integrity, audit logging, CI security testing, and human review provide layered protection.
