# Security Policy

Deputy is a supply-chain security tool, so we hold its own security to a high bar.

## Reporting a vulnerability

**Please do not open a public issue for security reports.**

Report privately through GitHub's **Security Advisories**: go to the repository's
**Security** tab → **Report a vulnerability**. This opens a private channel with the
maintainers.

Please include:

- a description of the issue and its impact,
- the affected crate(s) and version(s),
- reproduction steps or a proof of concept,
- any suggested remediation.

We aim to acknowledge a report within **3 business days** and to provide a remediation timeline
after triage. We will credit reporters who wish to be named once a fix ships.

## Scope

In scope: anything that weakens Deputy's guarantees — e.g. bypassing the fail-closed deploy
gate, breaking at-rest encryption or the audit chain, accepting a forged mID token, accepting a
tampered or substituted dependency, or breaking the integrity of the cross-device sync.

Out of scope: vulnerabilities in third-party dependencies (report those upstream), though we
welcome a heads-up so we can pin or patch.

## Supported versions

Deputy is pre-1.0; security fixes land on the latest `0.x` release. Pin exact versions and rely
on `Cargo.lock` for reproducible builds.
