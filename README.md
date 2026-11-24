# Strix Traffic-Control Gateway

An upstream security and compliance gateway for authorized Web Application Penetration Testing (VAPT), enforcing strict scope boundary allowlisting, rate-limit governance, and DNS rebinding protections.

---

## 1. Architecture & Threat Model

```
┌─────────────────────────────────┐
│     Strix Agent Sandbox         │
│  (Autonomous security agents)   │
└────────────────┬────────────────┘
                 │ (HTTP / HTTPS Proxy)
                 ▼
┌─────────────────────────────────┐
│             Caido               │
│   (Interception & Traffic Log)  │
└────────────────┬────────────────┘
                 │ (Upstream Forwarding)
                 ▼
┌─────────────────────────────────┐
│   mitmproxy Upstream Gateway    │
│    (Traffic-Control Gateway)    │
│  ┌───────────────────────────┐  │
│  │ Exact Host Allowlist      │  │
│  │ (Target Host ONLY)        │  │
│  ├───────────────────────────┤  │
│  │ DNS Rebinding Protection  │  │
│  │ (Public IP + TOCTOU Pin)  │  │
│  ├───────────────────────────┤  │
│  │ SQLite Durable Limiter    │  │
│  │ (<= 5 req / 60s Durable)  │  │
│  ├───────────────────────────┤  │
│  │ Protocol Defense          │  │
│  │ (No raw TCP / WebSockets) │  │
│  ├───────────────────────────┤  │
│  │ Bounded Queue (504 TO)    │  │
│  ├───────────────────────────┤  │
│  │ Zero-PII Sanitized Logger │  │
│  ├───────────────────────────┤  │
│  │ Fail-Closed Enforcer      │  │
│  └───────────────────────────┘  │
└────────────────┬────────────────┘
                 │ (Forwarded ONLY if admitted & verified)
                 ▼
┌─────────────────────────────────┐
│      Authorized Target          │
│    `target.example.com`         │
│   (Ports 80 HTTP / 443 HTTPS)   │
└─────────────────────────────────┘
```

The gateway sits as the authoritative egress gatekeeper between **Caido** and the external network. Even if an automated tool or Strix agent attempts to issue aggressive scanning bursts, scan subdomains, or probe unauthorized IP literals, the gateway intercepts, throttles, and strictly blocks non-compliant requests before any packet leaves the assessment environment.

---

## 2. Core Security Controls & Invariants

| Requirement | Implementation & Guarantee | Verification |
|---|---|---|
| **1. Upstream Proxy** | mitmproxy (`mitmdump`) running addon `gateway/mitm_addon.py`. | Tested with `GatewayAddon` hooks. |
| **2. Global Rolling Limit** | Strict $\le$ 5 HTTP requests per 60 seconds across all concurrent agents, flows, and process restarts. | `RollingWindowLimiter` backed by SQLite. |
| **3. Request Queuing & Bounded Wait** | Saturated requests queue in FIFO order. If wait exceeds `queue_timeout` (default 30.0s), fails closed with HTTP 504 Gateway Timeout. | Verified in `test_queue_timeout_fails_closed_with_504`. |
| **4. Exact-Host Allowlist** | Only the configured target domain is permitted. IP literals (`127.0.0.1`, `[::1]`, target IPs), subdomains (`api.target.example.com`), and alternate hostnames (`attacker.com`) are rejected with `403 Forbidden`. | Verified in `test_destination_validation_*`. |
| **5. DNS Rebinding & TOCTOU Defense** | Validates resolved destination IPs against loopback, RFC 1918 private, link-local, multicast, reserved, and cloud metadata (`169.254.169.254`) ranges. Rejects mixed address sets. Pins address to prevent TOCTOU rebinding. | Verified in `TestDnsRebindingProtection`. |
| **6. Protocol & Tunnel Bypass Defense** | Conservative CONNECT rate-limiting; rejects opaque/unintercepted raw TCP streams (`tcp_start`); rejects WebSocket upgrade requests and streams (`websocket_start`); rejects UDP (`udp_start`). | Verified in `TestProtocolBypassDefense`. |
| **7. Durable Restart Persistence** | Stores admission timestamps in durable SQLite database with atomic `BEGIN IMMEDIATE` transactions. Detects clock rollback and database corruption, failing closed. | Verified in `TestSqlitePersistenceAndRollback`. |
| **8. Fail Closed** | Any validation error, limiter timeout, internal error, or malformed flow immediately results in an HTTP 403, 504, or 500 rejection; traffic is never forwarded. | Verified in `test_fail_closed_*`. |
| **9. No Automatic Retries** | Gateway never retries failed connections or dropped requests. Each flow is processed once. | Verified in `test_no_retries_*`. |
| **10. Zero-Credential Logging** | Logs strictly exclude cookies, authorization headers (`Bearer`, `Basic`, `X-Api-Key`), request/response bodies, and URL query strings (`?token=...`). Only sanitized paths and metrics are logged. | Verified in `TestZeroCredentialLogging`. |
| **11. Anti-Tamper & Immutability** | Gateway rules and target allowlists are read-only properties; client headers attempting to bypass limits (`X-Bypass-Rate-Limit`) are stripped. | Verified in `TestAntiBypassAndTamperResistance`. |

---

## 3. Directory Layout

```
gateway/
├── Dockerfile              # Hardened non-root Docker container specification
├── requirements.txt        # Runtime dependencies (mitmproxy, pytest)
├── limiter.py              # SQLite-backed durable rolling-window rate limiter
├── mitm_addon.py           # mitmproxy addon enforcing allowlist, DNS checks, queueing, and logging
├── README.md               # Architecture, deployment, and testing documentation
└── tests/
    ├── __init__.py         # Test package initializer
    ├── test_limiter.py     # Unit tests for RollingWindowLimiter (19 tests)
    └── test_mitm_addon.py  # Unit tests for GatewayAddon & policies (30 tests)
```

---

## 4. Components Detailed

### `limiter.py` — `RollingWindowLimiter`
- **Durable Persistence**: Backed by SQLite table `admissions (id INTEGER PRIMARY KEY, admitted_at REAL NOT NULL)`.
- **Atomic Transactions**: Uses `BEGIN IMMEDIATE` transactions to prevent race conditions across concurrent threads and processes.
- **Clock Rollback Detection**: Compares current time against maximum recorded admission timestamp; raises `ClockRollbackError` and fails closed if rollback is detected.
- **Corruption Resilience**: Executes integrity checks; fails closed with `RateLimitPersistenceError` on corrupted files.
- **Thread-Safe Async Lock**: Uses synchronized double-checked locking under `_state_lock` for `_get_async_lock()`.
- **Bounded Wait**: Raises `RateLimitTimeoutError` if calculated wait exceeds caller-specified timeout.

### `mitm_addon.py` — `GatewayAddon`
- **`is_safe_public_ip(ip_str)`**: Strict address filter rejecting loopback (`127.0.0.0/8`, `::1`), private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), cloud metadata (`169.254.169.254`), multicast, reserved, and unspecified addresses.
- **`resolve_and_validate_hostname(hostname, resolver)`**: Resolves hostname and verifies that *all* returned IPs are verified public addresses. Fails closed if mixed public/private sets are returned.
- **`server_connect(data)`**: Validates actual destination IP immediately prior to socket creation, eliminating TOCTOU DNS rebinding gaps.
- **`http_connect(flow)`**: Conservatively rate-limits `CONNECT` tunnel establishment and pins upstream destination address.
- **`request(flow)`**: Rejects WebSocket upgrades (`Upgrade: websocket`), validates destination host and Host header, rate-limits individual HTTP requests with bounded timeout, and strips bypass headers.
- **`tcp_start(flow)` / `websocket_start(flow)` / `udp_start(flow)`**: Kills unintercepted raw TCP streams, WebSocket sessions, and UDP flows.

---

## 5. Configuration Reference

Configuration is hardened at process launch. Default settings enforce strict penetration testing guardrails:

| Setting / Constant | Default Value | Description |
|---|---|---|
| `PERMITTED_HOST` | `target.example.com` (configurable) | Exact target domain authorized for testing. |
| `PERMITTED_PORTS` | `(80, 443)` | Permitted HTTP and HTTPS egress ports. |
| `DEFAULT_MAX_REQUESTS`| `5` | Maximum requests allowed in rolling window. |
| `DEFAULT_WINDOW_SECONDS` | `60.0` | Rolling window duration in seconds. |
| `DEFAULT_QUEUE_TIMEOUT` | `30.0` | Maximum queue delay before HTTP 504 Gateway Timeout. |
| `GATEWAY_LISTEN_PORT` | `8080` | Local port where mitmproxy listens for Caido traffic. |
| `GATEWAY_DB_PATH` | `/app/data/gateway_limiter.db` | Persistent SQLite database file path. |

---

## 6. Deployment & Integration Guide

### A. Containerized Deployment (Hardened Production Spec)

Build the hardened Docker container:
```bash
docker build -t strix-gateway:v1 gateway/
```

Run the container with read-only root filesystem, tmpfs for CA certificate generation, persistent data volume, and dropped capabilities:
```bash
docker run -d \
  --name strix-traffic-gateway \
  --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  --read-only \
  --tmpfs /home/gatewayuser/.mitmproxy:rw,noexec,nosuid,size=16m \
  --mount type=volume,source=gateway-data,target=/app/data \
  --cap-drop ALL \
  strix-gateway:v1
```

*Key container hardening features:*
- Runs as unprivileged user `gatewayuser` (UID 1000).
- Root filesystem is completely read-only (`--read-only`).
- Temporary `/home/gatewayuser/.mitmproxy` tmpfs allows dynamic mitmproxy CA generation without compromising root filesystem immutability.
- Persistent volume `/app/data` preserves SQLite rate-limit state across container restarts.
- All Linux kernel capabilities dropped (`--cap-drop ALL`).

### B. Upstream Caido Configuration

1. In Caido, navigate to **Settings** $\rightarrow$ **Upstream Proxy**.
2. Add a new upstream proxy:
   - **Protocol**: HTTP
   - **Host**: `127.0.0.1` (or gateway container IP)
   - **Port**: `8080`
3. **CA Certificate Trust**:
   - To inspect HTTPS traffic end-to-end, copy `mitmproxy-ca-cert.pem` from `/home/gatewayuser/.mitmproxy` to Caido's trusted CA certificates, or configure Caido's upstream proxy to disable TLS verification for local lab testing.
4. Route all Caido egress traffic through this upstream proxy.

### C. Strix Agent Sandbox Configuration

Configure the Strix environment to route all traffic to Caido:
```bash
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"
export NO_PROXY=""
```

Traffic pipeline: `Strix -> Caido (:8080) -> Gateway (:8080) -> target.example.com`.

---

## 7. Verification & Test Suite

The test suite contains 49 comprehensive unit tests covering:
- In-memory and SQLite-backed rolling window limits ($\le 5$ req / 60s).
- Persistence across process restarts.
- System clock rollback detection and fail-closed handling.
- SQLite database corruption fail-closed handling.
- Thread-safe lazy async lock initialization.
- Exact-host allowlisting and rejection of subdomains, IP literals, and alternate hosts.
- DNS rebinding protection (public allowed, private/loopback/cloud-metadata rejected, mixed sets rejected).
- TOCTOU address verification in `server_connect`.
- Conservative CONNECT rate limiting.
- Rejection of WebSocket upgrade requests and active WebSocket streams.
- Rejection of opaque raw TCP and UDP flows.
- Bounded queue wait timeout returning HTTP 504 Gateway Timeout.
- Zero-credential / zero-PII logging verification.
- Immutability and anti-bypass header stripping.

To run the complete test suite:
```bash
python -m pytest -v gateway/tests/
```

### Test Suite Execution Output
```
============================= test session starts =============================
platform win32 -- Python 3.13.11, pytest-8.3.5
rootdir: C:\Users\aryan\Documents\projects\VAPT
collected 49 items

gateway/tests/test_limiter.py::TestLimiterInitialization::test_default_initialization PASSED
gateway/tests/test_limiter.py::TestLimiterInitialization::test_invalid_max_requests_fails_closed PASSED
gateway/tests/test_limiter.py::TestLimiterInitialization::test_invalid_window_seconds_fails_closed PASSED
gateway/tests/test_limiter.py::TestLimiterInitialization::test_invalid_safety_margin_fails_closed PASSED
gateway/tests/test_limiter.py::TestRollingWindowBehavior::test_first_five_requests_admitted_immediately PASSED
gateway/tests/test_limiter.py::TestRollingWindowBehavior::test_sixth_request_waits_rather_than_forwarded_early PASSED
gateway/tests/test_limiter.py::TestRollingWindowBehavior::test_seventh_and_subsequent_requests_paced_strictly PASSED
gateway/tests/test_limiter.py::TestRollingWindowBehavior::test_window_expiration_allows_immediate_admission_after_lapse PASSED
gateway/tests/test_limiter.py::TestRollingWindowBehavior::test_strict_rolling_window_invariant_over_arbitrary_traffic PASSED
gateway/tests/test_limiter.py::TestAsyncLimiter::test_async_acquire_immediate_and_queued PASSED
gateway/tests/test_limiter.py::TestAsyncLimiter::test_async_concurrent_tasks_preserve_invariant PASSED
gateway/tests/test_limiter.py::TestConcurrencyAndThreads::test_multithreaded_concurrent_requests_preserve_rolling_invariant PASSED
gateway/tests/test_limiter.py::TestFailureModesAndFailClosed::test_timeout_raises_timeout_error_and_fails_closed PASSED
gateway/tests/test_limiter.py::TestFailureModesAndFailClosed::test_async_timeout_fails_closed PASSED
gateway/tests/test_limiter.py::TestFailureModesAndFailClosed::test_reset_clears_history_and_counters PASSED
gateway/tests/test_limiter.py::TestSqlitePersistenceAndRollback::test_persistence_across_process_restarts PASSED
gateway/tests/test_limiter.py::TestSqlitePersistenceAndRollback::test_clock_rollback_detected_and_fails_closed PASSED
gateway/tests/test_limiter.py::TestSqlitePersistenceAndRollback::test_database_corruption_fails_closed PASSED
gateway/tests/test_limiter.py::TestAsyncLockInitialization::test_concurrent_initialization_produces_identical_lock_instance PASSED
gateway/tests/test_mitm_addon.py::TestDestinationValidation::test_permitted_exact_hostname PASSED
gateway/tests/test_mitm_addon.py::TestDestinationValidation::test_reject_subdomains PASSED
gateway/tests/test_mitm_addon.py::TestDestinationValidation::test_reject_ip_literals PASSED
gateway/tests/test_mitm_addon.py::TestDestinationValidation::test_reject_alternate_and_unrelated_hosts PASSED
gateway/tests/test_mitm_addon.py::TestDestinationValidation::test_reject_unpermitted_ports PASSED
gateway/tests/test_mitm_addon.py::TestDestinationValidation::test_reject_empty_or_malformed PASSED
gateway/tests/test_mitm_addon.py::TestHttpsConnectValidation::test_connect_permitted_target_succeeds PASSED
gateway/tests/test_mitm_addon.py::TestHttpsConnectValidation::test_connect_unauthorized_destinations_fail_closed_with_403 PASSED
gateway/tests/test_mitm_addon.py::TestHttpRequestValidation::test_http_request_permitted_target PASSED
gateway/tests/test_mitm_addon.py::TestHttpRequestValidation::test_http_request_subdomain_rejected_with_403 PASSED
gateway/tests/test_mitm_addon.py::TestHttpRequestValidation::test_http_request_ip_literal_rejected_with_403 PASSED
gateway/tests/test_mitm_addon.py::TestHttpRequestValidation::test_host_header_spoofing_rejected_with_403 PASSED
gateway/tests/test_mitm_addon.py::TestRateLimiterIntegration::test_addon_enforces_rolling_rate_limit PASSED
gateway/tests/test_mitm_addon.py::TestRateLimiterIntegration::test_shared_limiter_across_independent_flows PASSED
gateway/tests/test_mitm_addon.py::TestRateLimiterIntegration::test_fail_closed_on_rate_limiter_error PASSED
gateway/tests/test_mitm_addon.py::TestZeroCredentialLogging::test_sensitive_artifacts_are_never_logged PASSED
gateway/tests/test_mitm_addon.py::TestAntiBypassAndTamperResistance::test_agent_bypass_headers_are_stripped PASSED
gateway/tests/test_mitm_addon.py::TestAntiBypassAndTamperResistance::test_configuration_immutability PASSED
gateway/tests/test_mitm_addon.py::TestNoRetries::test_error_hook_logs_without_retrying PASSED
gateway/tests/test_mitm_addon.py::TestProtocolBypassDefense::test_websocket_upgrade_rejected_with_403 PASSED
gateway/tests/test_mitm_addon.py::TestProtocolBypassDefense::test_tcp_start_kills_opaque_tunnel_flow PASSED
gateway/tests/test_mitm_addon.py::TestProtocolBypassDefense::test_websocket_start_kills_websocket_stream PASSED
gateway/tests/test_mitm_addon.py::TestProtocolBypassDefense::test_udp_start_kills_udp_flow PASSED
gateway/tests/test_mitm_addon.py::TestProtocolBypassDefense::test_connect_consumes_rate_limit_token PASSED
gateway/tests/test_mitm_addon.py::TestDnsRebindingProtection::test_public_ip_resolution_permitted PASSED
gateway/tests/test_mitm_addon.py::TestDnsRebindingProtection::test_private_ip_resolution_rejected_with_403 PASSED
gateway/tests/test_mitm_addon.py::TestDnsRebindingProtection::test_mixed_ip_resolution_rejected PASSED
gateway/tests/test_mitm_addon.py::TestDnsRebindingProtection::test_toctou_server_connect_blocks_private_ip PASSED
gateway/tests/test_mitm_addon.py::TestDnsRebindingProtection::test_toctou_server_connect_allows_public_ip PASSED
gateway/tests/test_mitm_addon.py::TestBoundedQueueTimeout::test_queue_timeout_fails_closed_with_504 PASSED

============================= 49 passed in 1.41s ==============================
```

---

## 8. Operational Status

**Production Readiness**: Verified and ready for deployment in testing pipelines. Local lab proxy integration (`Security Agent / Scanner` $\rightarrow$ `Caido` $\rightarrow$ `mitmproxy gateway`) ensures full compliance with assessment rate limits and boundary rules.
