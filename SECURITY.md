# Security Policy

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | ✅ Yes             |
| < 1.0   | ❌ No (Deprecated) |

## Reporting a Vulnerability

We take the security of Bastion seriously. If you find a security vulnerability, please **do not report it as a public issue.**

Instead, please send an ethical disclosure to:
**security@motivationstudio.llc**

### What to include:
- A clear description of the vulnerability.
- Steps to reproduce (Proof of Concept).
- Potential impact.

### Our Commitment:
- We will acknowledge your report within 48 hours.
- We will provide an estimated timeline for a fix.
- We will credit you in our security advisories (with your consent) if the vulnerability is validated.

## Defense-in-Depth Philosophy
Bastion is designed under the "Assume Breach" mentality. While we strive to prevent vulnerabilities, we recommend using Bastion alongside OS-level sandboxing (Docker, gVisor, etc.) for maximum protection.
