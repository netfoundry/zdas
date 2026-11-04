# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/netfoundry/zdas/security/advisories/new),
not in a public issue. Include the version or commit, what an attacker
needs, and how to reproduce it if you can.

You should get a reply within a few business days. Fixes ship in a new
release, with a GitHub security advisory once the fix is available.

## Security model

[docs/security.md](docs/security.md) describes what ZDAS enforces, what
operators and embedders must do, and the design decisions behind behavior
that can look like a gap. Please read it before reporting one of those.

## Supported versions

zdas is pre-1.0. Fixes go into the latest release only, so upgrade to it
to pick them up.

## Verifying release binaries

Release binaries from v0.13.0 on have a build provenance attestation. To
check that a binary was built from this repository by its release workflow:

```
gh attestation verify zdas-v0.13.0-linux-amd64 --repo netfoundry/zdas
```

`checksums-sha256.txt` in each release lists the SHA-256 of every binary.
