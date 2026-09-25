# Security Policy

Vanguard-SIEM is an offline-first defensive security application. Do not submit real military telemetry, credentials, tokens, private keys, personal data, or operational secrets in public issues or pull requests.

## Supported security baseline

The main branch is the maintained development line.

## Reporting a vulnerability

For a sensitive vulnerability, do not publish exploit details in a public issue. Contact the repository maintainer through the private security-reporting mechanism available to the project owner.

When reporting, include the affected component/version, security impact, reproducible defensive test case, and proposed mitigation if known.

Never include live credentials or sensitive operational evidence.

## Engineering expectations

Security-sensitive changes must preserve offline-first runtime behavior, bounded untrusted input handling, secret redaction, evidence provenance, append-only audit integrity, human approval for disruptive response, and regression/security test coverage.
