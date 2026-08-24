# Security Policy

If you believe you have found a security issue in Varden, please report it **privately**
before public disclosure.

## How to report

1. **Preferred:** use [GitHub private vulnerability reporting](https://github.com/markndg/varden/security/advisories/new) for this repository (available when the feature is enabled on the repo).
2. If that is unavailable, open a **draft** security advisory from the repository **Security** tab, or contact the maintainer through a non-public channel linked from the GitHub profile of the repository owner.

## What to include

- affected version or commit
- reproduction steps
- impact assessment
- suggested mitigation if known

Please avoid opening **public issues** for exploitable vulnerabilities until a fix is available.

## Provenance-aware authority flow

Varden's provenance subsystem treats client-supplied trust, delegation and
approval claims as untrusted unless verified by the control plane. Missing
or incomplete causal context is never silently labelled trusted. See
[`docs/provenance-limitations.md`](docs/provenance-limitations.md).
