# Vanguard-SIEM Threat Model

## Method
The threat model uses STRIDE, abuse-case analysis, and adversarial log/evasion testing.

## Assets
- Security logs and incident evidence
- Detection rules and engine code
- Credentials and authentication/session data
- Audit records
- Configuration
- Security reports
- System integrity

## Threat actors
- External attacker
- Malicious insider
- Compromised endpoint
- Malicious log producer
- Malicious evidence uploader
- Supply-chain attacker
- Compromised analyst account

## STRIDE matrix

| Threat | Example | Controls |
|---|---|---|
| Spoofing | Fake identity/source in telemetry | Authentication, validation, provenance |
| Tampering | Modified evidence | SHA-256 hashing and controlled evidence handling |
| Repudiation | Analyst denies an action | Audit trail |
| Information Disclosure | Token/password in logs | Sanitization and redaction |
| Denial of Service | Oversized/flooded upload | Upload and record limits, bounded processing |
| Elevation of Privilege | Unauthorized privileged activity | Detection rules, authorization controls, audit |

## Key attack scenarios

### Brute force
Repeated authentication failures from one or more sources are evaluated over a bounded time window.

### Network scanning
A source contacting many unique destinations within a bounded window can generate a behavioral detection.

### Web attacks
Normalized web telemetry is evaluated for SQL injection, XSS, path manipulation, and suspicious upload patterns.

### Log injection
Logs are treated as untrusted data. Content cannot modify detection logic or execute commands.

### Supply-chain compromise
Dependencies and source changes should be reviewed, tested, provenance-tracked, and included in CI security validation.

## Risk priorities
1. Malicious log input
2. Detection evasion
3. Credential disclosure
4. Alert flooding
5. Evidence tampering
6. Supply-chain compromise
7. Unauthorized analyst actions

## Security principle
A failed detection rule must not be treated as proof that no attack occurred. Correlation, behavioral detection, evidence integrity, and human review provide additional defensive layers.
