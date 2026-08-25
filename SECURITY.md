# Security Policy

Bollwark is a security service, so we take vulnerabilities in it seriously and
appreciate reports from the community.

## Reporting a Vulnerability

**Please do not open a public issue for security problems.**

Report privately through either channel:

- **GitHub** — use *Security → Report a vulnerability* on this repository
  ([private vulnerability reporting](https://github.com/hauju/bollwark-api/security/advisories/new)).
  This is the preferred channel.
- **Email** — <mail@haukejung.de>. Use `[SECURITY] bollwark` in the subject.

Please include enough detail to reproduce: affected version or commit, a
description of the issue, reproduction steps or a proof of concept, and the
impact you foresee.

## What to Expect

- **Acknowledgement** within 72 hours.
- **Assessment** and a target remediation timeline within 7 days.
- We'll keep you updated as we work on a fix and will credit you in the
  advisory once it's published, unless you prefer to stay anonymous.

Please give us a reasonable window to ship a fix before any public disclosure.

## Scope

This project is self-hosted software; there is no hosted service to test
against. Focus reports on the code in this repository — the puzzle engine, risk
scoring, API surface, browser widget, and admin dashboard.

Out of scope: findings that require a misconfigured deployment (e.g. an exposed
`ADMIN_TOKEN`, a trusted-proxy allowlist that trusts the public internet), or
reports about third-party infrastructure used to host a given instance.

## Supported Versions

Bollwark is pre-1.0. Security fixes land on `main` and in the most recent
release; there are no long-term support branches yet.
