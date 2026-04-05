# CWE Mapping — Software Supply Chain Failures (A03:2025)

## Primary CWEs for A03

| CWE ID | Name | Detection Tool | Code Pattern |
|--------|------|----------------|--------------|
| CWE-1104 | Use of Unmaintained Third-Party Component | pip-audit, safety | Component with no releases in 2+ years |
| CWE-1395 | Dependency on Vulnerable Third-Party Component | pip-audit, osv-scanner | Any CVE-bearing dependency |
| CWE-1329 | Reliance on Component That is Not Updateable | Manual review | Pinned to EOL version with no upgrade path |

## Extended CWEs relevant to supply chain context

| CWE ID | Name | Detection | Notes |
|--------|------|-----------|-------|
| CWE-426 | Untrusted Search Path | Bandit B322 | `sys.path.insert(0, ...)` with user-controlled path |
| CWE-494 | Download Without Integrity Check | Manual/CI check | Missing `--hash` in requirements |
| CWE-295 | Improper Certificate Validation | Bandit B501 | `verify=False` in requests/httpx |
| CWE-829 | Inclusion of Functionality from Untrusted Sphere | guarddog | Packages from unofficial indexes |
| CWE-693 | Protection Mechanism Failure | CI audit | No dependency scanning in pipeline |
| CWE-1357 | Reliance on Insufficiently Trustworthy Component | SBOM + audit | Transitive deps with no attestation |

## Mapping to OWASP Testing Guide (OTG)

| Test | CWE | Tool |
|------|-----|------|
| OTG-CONFIG-001: Network/Infrastructure Configuration | CWE-1104 | pip-audit |
| OTG-CONFIG-002: Application Platform Configuration | CWE-1395 | safety |
| OTG-SESS-001: Testing for Cookie Attributes | — | N/A for supply chain |

## CVSS Scoring Guidance for Reports

When filing findings against these CWEs, use the following CVSS vectors as templates:

### CWE-1395 (Vulnerable Component) — Remote Code Execution potential
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Base Score: 9.8 (Critical)
```

### CWE-1395 — Information Disclosure only
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
Base Score: 7.5 (High)
```

### CWE-1104 — Unmaintained component (no active CVE)
```
CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L
Base Score: 5.6 (Medium) — adjust based on component criticality
```

### CWE-494 — Missing integrity check
```
CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H
Base Score: 7.5 (High)
```

## Compliance Framework Cross-References

| Standard | Requirement | Maps to CWE |
|----------|-------------|-------------|
| NIST SP 800-218 (SSDF) | PO.3.2 — Use approved tools | CWE-1104, CWE-1395 |
| NIST SP 800-218 | PS.2 — Protect code from tampering | CWE-494 |
| US EO 14028 | SBOM requirement | CWE-1104 |
| SOC 2 CC6.8 | Unauthorized software | CWE-829 |
| ISO 27001 A.14.2.7 | Outsourced development | CWE-1395 |
| PCI DSS 6.3 | Identify security vulnerabilities | CWE-1395 |