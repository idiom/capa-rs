# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report security issues privately by emailing **security@yeti-sec.io** with:

- A description of the vulnerability and its potential impact.
- Steps to reproduce or a proof-of-concept (if available).
- Any suggested mitigations.

We aim to acknowledge reports within 48 hours and provide an initial assessment within 5 business days.

## Scope

capa-rs is a static analysis tool that reads untrusted binary files. Security-relevant areas include:

- **Binary parsing** (`capa-backend::loader`, `dotscope`) — malformed inputs must not cause panics or memory unsafety.
- **Rule parsing** (`capa-core::rule::parser`) — malformed YAML rules must return errors, not crash.
- **Feature extraction** (`capa-backend::extractor`) — analysis of adversarial samples must be safe to run.

Out of scope: issues in bundled `capa-rules/` YAML content (report those to [mandiant/capa-rules](https://github.com/mandiant/capa-rules)).
