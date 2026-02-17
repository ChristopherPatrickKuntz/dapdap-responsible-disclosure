# Security Advisory: Unauthenticated Server Profiling Endpoints and Client-Side Credential Exposure in dapdap.net

**Advisory ID:** CPK-2026-004
**Platform:** DapDap (dapdap.net / app.dapdap.net)
**Severity:** Critical
**CWE:** CWE-215 (Insertion of Sensitive Information Into Debugging Code), CWE-798 (Use of Hard-coded Credentials), CWE-942 (Permissive Cross-domain Policy)
**Affected Components:** `mainnet-api-monad.dapdap.net`, `testnet-api-monad.dapdap.net`, `test-api-cashback.dapdap.net`, `app.dapdap.net/_next/static/chunks/`
**Discovered:** 2026-02-17
**Reporter:** Christopher Patrick Kuntz -- CPK Solutions (christopher@cpk.solutions)

---

## Executive Summary

During passive analysis of publicly accessible endpoints and JavaScript bundles on `dapdap.net`, CPK Solutions identified **unauthenticated Go pprof debug endpoints** on three backend API servers, exposing complete server memory profiles, internal source code paths, function names, dependency versions, and runtime state to the public internet without authentication.

Additionally, **three third-party API credentials** were identified in client-side JavaScript bundles, including a **verified-live Infura RPC key** responding on Ethereum mainnet and Optimism.

All findings were obtained exclusively through analysis of publicly accessible content. **No credentials were tested beyond standard RPC liveness checks (read-only `eth_chainId`). No systems were probed beyond what a standard web browser or HTTP client performs when loading publicly served resources.**

**Immediate action recommended:** Disable or restrict pprof endpoints on all three affected hosts, and rotate the exposed Infura API key.

---

## Finding 1: Unauthenticated Go pprof Debug Endpoints (Critical)

| Severity | Impact | Difficulty |
|----------|--------|------------|
| **Critical** | **High** | **Low** |

**Validated:** Yes -- endpoints were accessed via standard unauthenticated HTTP GET requests; full heap dumps were returned and parsed.

### Description

Three backend API servers expose Go's `net/http/pprof` profiling endpoints to the public internet without any authentication. These endpoints return full server memory dumps, goroutine traces, allocation profiles, and thread creation data -- providing a complete x-ray of the server's internal architecture, source code structure, and runtime state.

| Host | Endpoint | Status |
|------|----------|--------|
| `mainnet-api-monad.dapdap.net` | `/pprof/heap?debug=1` | **Accessible** |
| `testnet-api-monad.dapdap.net` | `/pprof/heap?debug=1` | **Accessible** |
| `test-api-cashback.dapdap.net` | `/pprof/heap?debug=1` | **Accessible** |

The `gin-contrib/pprof` middleware is registered on Gin router initialization (`api/http/http.go`), serving all standard pprof endpoints: `heap`, `goroutine`, `allocs`, `threadcreate`, `block`, `mutex`, `cmdline`, and `symbol`.

### Information Exposed

The following categories of sensitive information are exposed to any unauthenticated visitor:

#### 1. Developer Identity and Project Structure

All server binaries were compiled from source under `/root/liuhy_projects/` on the host filesystem. Two distinct codebases are exposed:

| Codebase | Host | Entry Point |
|----------|------|-------------|
| `monad-backend-mainnet` | mainnet-api-monad, testnet-api-monad | `api/cmd/main/main.go` |
| `cashback-backend` | test-api-cashback | `api/cmd/main/main.go` |

All services are running as **root**.

#### 2. Complete API Route Map

Every HTTP handler function name is leaked via heap allocation traces, revealing the full API surface:

**monad-backend (21 handlers):**

| Handler | Implied Function |
|---------|-----------------|
| `login` | Authentication |
| `userInfo` | User profile retrieval |
| `userNft` | User NFT holdings |
| `userNotificationUnRead` | Notification state |
| `tokens` | Token listings |
| `tokensPrice` | Price data |
| `tokenMarket` | Market data |
| `tokenTrend5Minute` | 5-minute price trends |
| `recommendTokens` | Token recommendations |
| `transactions` | Transaction history |
| `bondingTransactions` | Bonding curve transactions |
| `rpRecords` | Reward point records |
| `topRpRanking` | RP leaderboard |
| `apps` | Application listings |
| `createEuphoriaOrder` | Game order creation |
| `latestEuphoria` | Game state |
| `euphoriaLeaderBoardWeek` | Weekly game leaderboard |
| `gameUser` | Game user profile |
| `gameAnnouncement` | Game announcements |
| `track` | User activity tracking |
| `checkAuth` | Authentication middleware |

**cashback-backend (7 handlers):**

| Handler | Implied Function |
|---------|-----------------|
| `activityList` | Cashback activities |
| `rewardList` | Reward listings |
| `rewardStats` | Reward statistics |
| `unClaimRewards` | Unclaimed rewards |
| `tradeList` | Trade history |
| `allTokenPrice` | Token prices |
| `role` | User role/permissions |

#### 3. Complete Source File Map

53 internal `.go` source files are exposed for `monad-backend-mainnet` and 20 for `cashback-backend`, organized in a standard layered architecture:

```
monad-backend-mainnet/
├── api/
│   ├── cmd/main/main.go          # Entry point
│   ├── conf/config.go            # Configuration
│   ├── dao/                      # Data access layer (14 files)
│   │   ├── user.go, token.go, transaction.go, bonding.go
│   │   ├── game_euphoria.go, game_deathfun.go, game_spin.go
│   │   ├── rp.go, price.go, magic.go, social.go
│   │   ├── notification.go, track.go, app.go, init.go
│   ├── http/                     # HTTP handlers (12 files)
│   │   ├── auth.go, user.go, token.go, transaction.go
│   │   ├── bonding.go, rp.go, game_euphoria.go, game_spin.go
│   │   ├── notification.go, track.go, app.go, http.go
│   ├── service/                  # Business logic (12 files)
│   │   ├── user.go, token.go, transaction.go, bonding.go
│   │   ├── game_euphoria.go, game.go, game_spin.go
│   │   ├── rp.go, notification.go, track.go, app.go, init.go
│   └── gin/                      # Middleware
│       ├── log.go, recovery.go, context.go
├── common/
│   ├── business/dao/             # Shared data access
│   │   ├── price.go, token.go, user.go
│   ├── business/model/model.go   # Data models
│   ├── redis/redis.go            # Redis with distributed locking
│   ├── http/http.go              # HTTP client utilities
│   ├── log/log.go                # Logging
│   ├── stack/stack.go            # Stack trace utilities
│   └── util/thread/thread.go     # Thread utilities
```

#### 4. Dependency Tree with Exact Versions

| Package | Version | Purpose |
|---------|---------|---------|
| `gin-gonic/gin` | v1.10.0 | HTTP framework |
| `gin-contrib/cors` | v1.7.2 | CORS middleware |
| `gomodule/redigo` | v1.9.2 | Redis client |
| `jackc/pgx/v5` | v5.5.5 | PostgreSQL driver |
| `gorm.io/gorm` | v1.25.12 | ORM |
| `gorm.io/driver/postgres` | v1.5.9 | PostgreSQL GORM driver |
| `sirupsen/logrus` | v1.9.3 | Structured logging |
| `shopspring/decimal` | v1.4.0 | Decimal arithmetic |
| `swaggo/files` | v1.0.1 | Swagger UI assets |
| `mailru/easyjson` | v0.7.6 | Fast JSON serialization |
| `jinzhu/inflection` | v1.0.0 | Name inflection |
| `mmcloughlin/addchain` | v0.4.0 | Addition chain computation |
| `aws/aws-sdk-go-v2/service/sts` | v1.23.2 | AWS STS (cashback only) |
| `go-playground/validator/v10` | v10.20.0 | Input validation (cashback only) |
| `golang.org/x/net/webdav` | v0.25.0 | WebDAV (cashback only) |

**Go runtime versions:**
- mainnet-api-monad: Go 1.24.9 (linux/amd64)
- testnet-api-monad, test-api-cashback: Go 1.22.2 (linux/amd64)

#### 5. Infrastructure Details

| Component | Technology | Evidence |
|-----------|-----------|----------|
| Database | PostgreSQL | `pgx/v5` connection traces in heap (pgconn.connect, pgconn.ConnectConfig) |
| Cache | Redis | `redigo` with distributed locking (WithNewLockTimeout, delRedisLock, updateLock) |
| Web Framework | Gin v1.10.0 | Router initialization visible in goroutine dump |
| Cloud Provider | AWS (cashback) | AWS STS role assumption (`aws-sdk-go-v2/service/sts@v1.23.2`) |

### Impact Assessment

The pprof endpoints provide an attacker with a complete reconnaissance package that would normally require source code access:

1. **API surface mapping** -- Every handler function is named, enabling targeted fuzzing of all 28+ API routes
2. **Dependency exploitation** -- Pinned versions allow immediate CVE lookup against all dependencies
3. **Architecture understanding** -- The full DAO/service/handler layer separation, Redis locking patterns, and database query paths are visible, enabling targeted SQL injection or business logic attacks
4. **Memory profiling** -- Repeated heap dumps reveal allocation patterns and can identify memory-based denial-of-service vectors
5. **AWS role assumption** -- The cashback backend uses AWS STS, indicating IAM role access to additional AWS services

**Note:** While this information dramatically lowers the barrier for targeted attacks, we did not identify direct credential exposure (e.g., database passwords, private keys) in the pprof output. The exposure is reconnaissance-grade information disclosure, not direct credential leakage.

### Recommendation

1. **Immediately** remove `gin-contrib/pprof` from production router initialization, or restrict it behind authentication and internal-only network access.
2. **Audit** whether any pprof data was accessed by unauthorized parties (check access logs for `/pprof/` requests).
3. **Avoid running services as root** -- use a dedicated service user with minimal permissions.

---

## Finding 2: Infura RPC API Key Exposed in Client-Side JavaScript -- Verified Live (Medium)

| Severity | Impact | Difficulty |
|----------|--------|------------|
| **Medium** | **Medium** | **Low** |

**Validated:** Partial -- a single read-only `eth_chainId` call confirmed the key is live on Ethereum mainnet and Optimism. No authenticated or state-changing requests were made.

### Description

An Infura API key is embedded in a production JavaScript bundle and was detected by TruffleHog with **verified-live** status. The key responds to standard RPC calls on multiple chains.

| Component | Value |
|-----------|-------|
| API Key | `388c7222...ba2c` [REDACTED] |
| Endpoint | `https://mainnet.infura.io/v3/{key}` |
| Source File | `9174-0557c071b896800a.js` |
| Verification | `eth_chainId` → `0x1` (Ethereum mainnet), `0xa` (Optimism) |

### Impact Assessment

The key is active on at least Ethereum mainnet and Optimism. An attacker can use it to:

- Consume DapDap's paid Infura API quota
- Route their own RPC traffic through DapDap's account
- Potentially cause service degradation if rate limits are reached

**Note:** RPC keys provide read access and transaction submission capabilities, but cannot move funds without a corresponding private key signature. The liveness check performed (`eth_chainId`) is a read-only, non-authenticated call.

### Recommendation

1. Rotate the Infura API key immediately.
2. Proxy RPC calls through a server-side backend.
3. Apply domain restrictions or IP allowlists on the replacement key.

---

## Finding 3: Unizen Auth Key Exposed in Client-Side JavaScript (Medium)

| Severity | Impact | Difficulty |
|----------|--------|------------|
| **Medium** | **Medium** | **Low** |

**Validated:** No -- key was observed in client-side source code only. No API calls were made to Unizen's service.

### Description

A Unizen cross-chain swap aggregator authentication key is embedded in a production JavaScript bundle and assigned to the variable `UNIZEN_AUTH_KEY`.

| Component | Value |
|-----------|-------|
| Key | `c3355f36-...0759` [REDACTED] |
| Variable | `UNIZEN_AUTH_KEY` |
| Source File | `pages/all-in-one/[chain]/[menu]-2adf9bffe4bf3610.js` |

### Impact Assessment

The key authenticates requests to Unizen's swap aggregation API. Exposure allows third parties to make API calls under DapDap's account, potentially consuming quota or performing swaps attributed to DapDap.

### Recommendation

Rotate the Unizen API key and move swap aggregation calls server-side.

---

## Finding 4: Dolomite Subgraph API Key Exposed in Client-Side JavaScript (Low)

| Severity | Impact | Difficulty |
|----------|--------|------------|
| **Low** | **Low** | **Low** |

**Validated:** No -- key was observed in client-side source code only. No API calls were made to Dolomite's service.

### Description

A Dolomite subgraph API key is embedded in a production JavaScript bundle, used for querying `subgraphapi.dolomite.io/api/public`.

| Component | Value |
|-----------|-------|
| Key | `1301d2d1-...1549` [REDACTED] |
| Endpoint | `subgraphapi.dolomite.io/api/public` |
| Source File | `src-config-caf7b01535217dde.js` |

### Recommendation

Move subgraph queries server-side or apply domain restrictions.

---

## Finding 5: CORS Wildcard on Application Domain (Low)

| Severity | Impact | Difficulty |
|----------|--------|------------|
| **Low** | **Low** | **Low** |

**Validated:** Yes -- wildcard `Access-Control-Allow-Origin: *` header confirmed in standard HTTP response.

### Description

The `app.dapdap.net` application returns `Access-Control-Allow-Origin: *`, allowing any website to read API responses in a user's browser context via cross-origin requests.

| Header | Value |
|--------|-------|
| `Access-Control-Allow-Origin` | `*` |
| Affected Host | `app.dapdap.net` |

### Impact Assessment

For a DeFi aggregator that handles user wallet interactions, a wildcard CORS policy allows malicious websites to read user-specific API responses (balances, positions, transaction history) if the user visits the malicious site while authenticated. This does not enable fund theft directly (transactions require wallet signature), but it exposes user financial data.

### Recommendation

Restrict `Access-Control-Allow-Origin` to specific trusted origins instead of using a wildcard.

---

## Finding 6: Missing Security Headers (Informational)

| Severity | Impact | Difficulty |
|----------|--------|------------|
| **Informational** | **Informational** | **N/A** |

**Validated:** Yes -- HTTP response headers inspected via standard request.

### Description

The application is missing standard security headers:

| Header | Status |
|--------|--------|
| `Content-Security-Policy` | Missing |
| `X-Frame-Options` | Missing |
| `X-Content-Type-Options` | Missing |
| `Permissions-Policy` | Missing |
| `Referrer-Policy` | Missing |

Only `Strict-Transport-Security` is present.

### Recommendation

Add standard security headers via CDN, reverse proxy, or application middleware.

---

## Architectural Observation

The pprof exposure (Finding 1) and the credential exposures (Findings 2-4) stem from two distinct root causes:

1. **Debug middleware left enabled in production** -- The `gin-contrib/pprof` package registers profiling routes by default when called. This should be gated behind a build tag or environment variable check, disabled entirely in production deployments.

2. **Client-side credential embedding** -- API keys for Infura, Unizen, and Dolomite are bundled into Next.js JavaScript chunks served to every visitor. The standard remediation is a server-side API proxy that holds credentials in environment variables.

---

## Scope and Methodology

This finding was discovered during a passive (non-intrusive) external security assessment of `dapdap.net`. The assessment included:

- **Subdomain enumeration**: Passive discovery of 45 subdomains via certificate transparency and DNS enumeration
- **JavaScript bundle analysis**: Static analysis of publicly served JavaScript files from `app.dapdap.net`
- **Secret detection**: Automated scanning using Gitleaks and TruffleHog
- **Nuclei scanning**: Template-based detection of exposed debug endpoints across all discovered subdomains
- **pprof analysis**: Parsing of publicly accessible heap, goroutine, and allocation profiles to catalog exposed information
- **RPC liveness check**: A single read-only `eth_chainId` call to verify the Infura key is active (no authenticated or state-changing requests)

**No private systems were accessed.** All data referenced in this advisory is publicly available: the JavaScript bundles are served to every visitor, the pprof endpoints respond to unauthenticated HTTP GET requests, and the RPC liveness check is a standard read-only JSON-RPC call.

---

## Severity Definitions

| Severity | Definition |
|----------|------------|
| **Critical** | Unauthenticated access to server internals that exposes complete application architecture, source code structure, dependency versions, and runtime state -- providing a comprehensive reconnaissance package for targeted attacks. |
| **Medium** | Exposed credential for a paid or rate-limited service, verified active. Potential for billing abuse or service disruption. |
| **Low** | Exposed credential for a public or low-sensitivity service, or a configuration weakness with limited direct impact. |
| **Informational** | Observation relevant to security posture but not directly exploitable. |

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-02-17 04:30 UTC | Vulnerabilities identified via automated scan (CPK Scanner, passive mode) |
| 2026-02-17 05:19 UTC | pprof analysis completed, full exposure catalog compiled |
| 2026-02-17 05:44 UTC | Advisory drafted and verified |
| 2026-02-17 05:50 UTC | Initial notification sent to DapDap team |
| 2026-05-18 | **Disclosure deadline: 90 days from initial report** |

This advisory follows the [disclose.io](https://disclose.io/) Core Terms for responsible vulnerability disclosure. We adhere to a 90-day disclosure window, after which the advisory may be published regardless of remediation status, consistent with industry standard practice (Google Project Zero, CERT/CC, Trail of Bits).

---

## References

- [CWE-215: Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-942: Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)
- [Go pprof Documentation](https://pkg.go.dev/net/http/pprof)
- [OWASP Testing Guide: Testing for Credentials in Source Code](https://owasp.org/www-project-web-security-testing-guide/)
- [disclose.io Core Terms](https://github.com/disclose/dioterms/blob/master/core-terms-vdp.md)

---

*This advisory is reported in good faith under responsible disclosure principles. No credentials were tested beyond a single read-only RPC liveness check (`eth_chainId`). No funds were moved, no contracts were interacted with, no authentication was bypassed, and no automated exploitation was performed. The pprof endpoints were accessed via standard unauthenticated HTTP GET requests to publicly routable URLs -- no access controls were circumvented. All analysis was conducted using publicly available data.*

*Christopher Patrick Kuntz -- CPK Solutions*
*christopher@cpk.solutions*
