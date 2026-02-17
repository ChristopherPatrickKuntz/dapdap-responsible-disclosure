# DapDap Responsible Disclosure -- CPK-2026-004

> **CONFIDENTIAL** -- This repository contains full technical details of unpatched vulnerabilities including exposed server profiling endpoints and client-side credential exposure. Do not share or publish until the disclosure deadline (2026-05-18) or vendor remediation, whichever comes first.

## Repository Structure

```
.
├── README.md                          # This file -- overview and index
├── ADVISORY.md                        # Full security advisory (submitted to vendor)
├── METHODOLOGY.md                     # Assessment methodology and tooling
├── evidence/
│   └── (gitignored -- local only)
└── methodology/
    └── pprof-analysis.md              # pprof endpoint analysis methodology
```

## Quick Reference

| Field | Value |
|-------|-------|
| **Advisory ID** | CPK-2026-004 |
| **Target** | DapDap (dapdap.net / app.dapdap.net) |
| **Severity** | Critical |
| **CWE** | CWE-215, CWE-798, CWE-942 |
| **Critical Finding** | Unauthenticated Go pprof debug endpoints on 3 backend API servers |
| **Exposed Credentials** | Infura RPC key (verified live), Unizen auth key, Dolomite subgraph key |
| **Affected Hosts** | `mainnet-api-monad.dapdap.net`, `testnet-api-monad.dapdap.net`, `test-api-cashback.dapdap.net` |
| **Subdomains Discovered** | 45 |
| **Discovery Date** | 2026-02-17 |
| **Disclosure Deadline** | 2026-05-18 (90 days) |

## Documents

- **[ADVISORY.md](ADVISORY.md)** -- The complete advisory as submitted to the DapDap team. This is the primary deliverable.
- **[METHODOLOGY.md](METHODOLOGY.md)** -- How the vulnerabilities were found, what tools were used, and the verification process.

## Disclosure Status

- [x] Vulnerabilities identified via automated scan (2026-02-17)
- [x] pprof analysis completed, full exposure catalog compiled (2026-02-17)
- [x] Advisory drafted and verified (2026-02-17)
- [x] Submitted to vendor (2026-02-17)
- [ ] Vendor acknowledgment received
- [ ] Vendor remediation confirmed
- [ ] Public disclosure

---

*CPK Solutions -- Automated Web3 Security Assessment*
