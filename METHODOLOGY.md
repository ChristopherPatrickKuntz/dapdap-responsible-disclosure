# Assessment Methodology -- DapDap (dapdap.net)

**Advisory ID:** CPK-2026-004
**Assessment Type:** Passive External Security Assessment (Sidewalk Mode)
**Date:** 2026-02-17
**Assessor:** Christopher Patrick Kuntz -- CPK Solutions (christopher@cpk.solutions)

---

## 1. Assessment Scope

### In Scope
- Publicly accessible web application at `https://app.dapdap.net`
- Client-side JavaScript bundles served to all visitors
- Publicly routable backend API servers discovered via subdomain enumeration
- DNS records, HTTP headers, and security configuration
- Associated subdomains of `dapdap.net`

### Out of Scope
- Server-side infrastructure beyond publicly exposed endpoints
- Authenticated functionality
- Smart contract source code (not analyzed beyond public deployment metadata)
- Any active exploitation, credential testing, or interaction with deployed contracts
- Third-party services (Infura, Unizen, Dolomite)
- Database or Redis instances (connection traces observed in pprof but not accessed)

### Assessment Profile

This assessment was conducted in **sidewalk mode** -- a passive, non-intrusive scan profile that:
- Does NOT attempt authentication
- Does NOT submit forms or modify state
- Does NOT interact with smart contracts
- Does NOT test or validate exposed credentials (beyond a single read-only RPC call)
- Does NOT perform active exploitation
- ONLY analyzes publicly served content, publicly accessible endpoints, and public blockchain data

---

## 2. Discovery Phase

### 2.1 Subdomain Enumeration

Passive subdomain enumeration identified 45 subdomains across `dapdap.net`:

```
app.dapdap.net                mainnet-api-monad.dapdap.net   testnet-api-monad.dapdap.net
test-api-cashback.dapdap.net  api.dapdap.net                 test-api.dapdap.net
test-api-monad.dapdap.net     test-api-metro.dapdap.net      dev-api-monad.dapdap.net
dev-stream-monad.dapdap.net   mainnet-stream-monad.dapdap.net
beratown.dapdap.net           mainnet.beratown.dapdap.net    testnet.beratown.dapdap.net
superswap.dapdap.net          superbridge.dapdap.net         super-bridge.dapdap.net
eureka.dapdap.net             alpha.dapdap.net               prod.dapdap.net
test.dapdap.net               test-monad.dapdap.net          test-nadsa.dapdap.net
qa-eureka.dapdap.net          qa-linea-swap.dapdap.net       qa-new-ui.dapdap.net
blog.dapdap.net               doc.dapdap.net                 docs.dapdap.net
asset.dapdap.net              assets.dapdap.net              analytics.dapdap.net
berachain.dapdap.net          mobilebera.dapdap.net          dev.bera.dapdap.net
scroll.dapdap.net             polygon.dapdap.net             linea.dapdap.net
blast.dapdap.net              orbiter.dapdap.net             mail.dapdap.net
testnet.base.dapdap.net       08-27-2024.dapdap.net          _beratown.dapdap.net
www.dapdap.net
```

HTTP probing confirmed `app.dapdap.net` as the primary application frontend (Next.js SPA). Multiple backend API servers were identified at `*-api-*.dapdap.net` subdomains.

### 2.2 JavaScript Bundle Analysis

CPK Scanner's JavaScript discovery module identified and downloaded all JavaScript bundles served by `app.dapdap.net`. The primary discovery methods:

1. **Katana crawler** -- Headless browser-based crawler that follows links, discovers dynamically loaded scripts, and captures the full set of JavaScript assets served during a standard page load.
2. **LinkFinder** -- Static analysis of discovered JavaScript files to extract additional script references, API endpoints, and URLs.
3. **Waymore / GAU** -- Historical URL analysis via the Wayback Machine and other URL aggregation sources to identify previously served JavaScript bundles.

### 2.3 Automated Secret Detection

Two complementary secret scanning tools were run against the collected JavaScript bundles:

1. **Gitleaks v8.22.1** -- Pattern-based secret scanner with 190+ rules (160 default + 30 custom Web3 rules). Custom rules include patterns for blockchain private keys, exchange API credentials, RPC provider API keys, and DeFi-specific secrets.

2. **TruffleHog v3** -- Entropy-based and pattern-based secret scanner. TruffleHog's Infura detector flagged the exposed key and performed automated verification, confirming it as **verified live**.

### 2.4 Nuclei Template Scanning

Nuclei was run against all 45 discovered subdomains with security-focused templates:

- **Exposed debug endpoints** -- Detected Go pprof debug pages on 3 backend API servers
- **Missing SRI** -- Detected missing Subresource Integrity on `docs.dapdap.net`
- **Security headers** -- Identified missing security headers across the application

### 2.5 pprof Endpoint Analysis

Upon Nuclei's detection of exposed Go pprof endpoints, a manual analysis was conducted by requesting the following standard pprof endpoints via unauthenticated HTTP GET:

| Endpoint | Purpose | Data Returned |
|----------|---------|---------------|
| `/pprof/heap?debug=1` | Heap memory profile | Full memory allocation traces with source file paths, function names, and dependency versions |
| `/pprof/goroutine?debug=1` | Active goroutines | Running goroutine stack traces showing active connections and operations |
| `/pprof/allocs?debug=1` | Allocation profile | Cumulative allocation traces |

The returned data was parsed to catalog:
- Internal source file paths (53 `.go` files for monad-backend, 20 for cashback-backend)
- HTTP handler function names (28 total across both backends)
- Third-party dependency versions (15 packages with exact versions)
- Infrastructure details (database, cache, cloud provider, Go runtime version)
- Developer identity information (filesystem paths)

**No pprof endpoints requiring POST requests or binary downloads were accessed** (e.g., `/pprof/profile` for CPU profiling was not requested, as it would impose load on the server).

---

## 3. Verification Phase

### 3.1 Credential Context Analysis

Each identified credential was verified through static analysis of the surrounding code context:

| Credential | Verification Method |
|------------|-------------------|
| Infura RPC key | TruffleHog verified-live detection + single `eth_chainId` call confirming response on Ethereum mainnet (`0x1`) and Optimism (`0xa`) |
| Unizen auth key | `UNIZEN_AUTH_KEY` variable assignment in JavaScript source, swap aggregator API context |
| Dolomite subgraph key | UUID in `subgraphapi.dolomite.io/api/public` endpoint context |

### 3.2 Firebase Key Classification

A Firebase/Google API key (`AIzaSyDhx...khQ`) was identified and verified via the public `getProjectConfig` endpoint. It returned the NEAR FastAuth Firebase project (`near-fastauth-prod`), confirming it as a **NEAR wallet infrastructure key** integrated by DapDap. Firebase web API keys are public by design and were classified accordingly (not elevated to a credential finding).

### 3.3 pprof Verification

The pprof endpoints were verified by parsing the returned text-format heap dumps. Verification confirmed:
- Real Go heap allocation data (not cached or placeholder responses)
- Active database connections (PostgreSQL via pgx/v5)
- Active Redis connections (redigo distributed locking)
- Real source file paths under `/root/liuhy_projects/`

### 3.4 CORS Verification

CORS configuration was verified by sending an HTTP request with `Origin: https://evil.com` and observing the response header `Access-Control-Allow-Origin: *`, confirming the wildcard policy.

### 3.5 Explicit Non-Actions

The following actions were **NOT** performed:

- No Infura API calls were made beyond a single read-only `eth_chainId` (no authenticated or state-changing requests)
- No Unizen API calls were made using the exposed auth key
- No Dolomite API calls were made using the exposed subgraph key
- No attempt was made to access the PostgreSQL database or Redis instances identified in pprof traces
- No attempt was made to exploit the AWS STS role assumption identified in the cashback backend
- No CPU profiling requests were made (which would impose server load)
- No smart contract interactions were performed
- No attempt was made to access authenticated API routes revealed by the handler function names

---

## 4. Severity Assessment

### Assessment Methodology

Severity was assessed based on:
1. **Exposure type** -- Server internals (Critical) vs. third-party credential (Medium) vs. configuration (Low)
2. **Information sensitivity** -- Complete application architecture (Critical) vs. single API key (Medium) vs. header configuration (Informational)
3. **Validation status** -- Verified accessible/live (higher) vs. observed in source only (lower)
4. **Potential for chained attacks** -- pprof data enables targeted follow-on attacks (Critical amplifier)

### Severity Assignment

| Finding | Severity | Rationale |
|---------|----------|-----------|
| pprof debug endpoints (3 hosts) | **Critical** | Unauthenticated access to full server internals: source tree, function names, dependency versions, memory state |
| Infura RPC key (verified live) | Medium | Active paid RPC key, billing/quota abuse potential |
| Unizen auth key | Medium | Authentication credential for swap aggregation API |
| Dolomite subgraph key | Low | Read-only subgraph API key, labeled "public" in endpoint URL |
| CORS wildcard | Low | Allows cross-origin data reads, limited direct impact |
| Missing security headers | Informational | Standard hardening gap |

---

## 5. Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| CPK Scanner | v2.x (sidewalk mode) | Orchestration, JavaScript discovery, pattern scanning |
| Katana | Latest | Headless crawling and JS discovery |
| LinkFinder | Latest | JavaScript static analysis for URLs and endpoints |
| Gitleaks | 8.22.1 | Secret pattern detection (190+ rules) |
| TruffleHog | v3 | Entropy-based secret detection with live verification |
| Nuclei | Latest | Template scanning (debug endpoints, headers, SRI) |
| Waymore / GAU | Latest | Historical URL discovery |
| curl | System | Manual pprof endpoint retrieval and CORS verification |
| Manual analysis | -- | pprof dump parsing, code context review |

---

## 6. Limitations

1. **Limited credential validation** -- Only the Infura key was verified for liveness (single read-only `eth_chainId`). Unizen and Dolomite keys were not tested. All impact assessments for untested keys are conditional.

2. **Minified source only** -- All JavaScript was analyzed in its minified/bundled form. Some API context may have been lost to minification.

3. **No server-side analysis** -- This was a client-side and publicly-accessible-endpoint assessment. Additional vulnerabilities may exist in authenticated API routes, server-side code, or internal infrastructure.

4. **pprof text format only** -- Only the human-readable `?debug=1` text format was requested. Binary pprof profiles (which could be loaded into `go tool pprof` for deeper analysis) were not downloaded.

5. **No CPU profiling** -- The `/pprof/profile` endpoint (which records a 30-second CPU profile and imposes server load) was not accessed. Only read-only, zero-impact endpoints were used.

6. **Single point-in-time** -- The assessment reflects the state of `dapdap.net` at 2026-02-17 04:30 UTC. Endpoints may have been secured or credentials rotated since.

---

*This methodology document is part of the CPK-2026-004 responsible disclosure package.*
