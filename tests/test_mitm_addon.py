"""Unit tests for the mitmproxy Traffic-Control Gateway Addon.

Tests:
1. Exact-hostname allowlisting (lunai.dpdns.org only).
2. Rejection of subdomains, IP literals, and alternate hostnames.
3. Destination validation on both HTTP requests and HTTPS CONNECT tunnels.
4. Global rolling rate limiter integration and queuing.
5. Fail-closed security on validation and limiter failures.
6. Zero-credential / zero-PII logging verification.
7. Anti-tampering, immutability, and header stripping.
8. Shared limiter across multiple distinct flows.
9. No automated retries.
"""

from __future__ import annotations

import asyncio
import io
import logging
from typing import Any, Dict, Optional
import pytest

from gateway.limiter import RateLimitError, RollingWindowLimiter
from gateway.mitm_addon import (
    PERMITTED_HOST,
    PERMITTED_PORTS,
    GatewayAddon,
    format_sanitized_log,
    validate_destination,
)


class MockRequest:
    """Mock HTTP request object matching mitmproxy.http.Request interface."""

    def __init__(
        self,
        method: str = "GET",
        scheme: str = "http",
        host: str = "lunai.dpdns.org",
        port: int = 80,
        path: str = "/",
        pretty_host: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        content: bytes = b"",
    ) -> None:
        self.method = method.upper()
        self.scheme = scheme.lower()
        self.host = host
        self.port = port
        self.path = path
        self.pretty_host = pretty_host if pretty_host is not None else host
        self.headers: Dict[str, str] = headers or {"Host": host}
        self.content = content


class MockFlow:
    """Mock HTTP flow matching mitmproxy.http.HTTPFlow interface."""

    def __init__(self, request: MockRequest) -> None:
        self.request = request
        self.response: Any = None
        self.error: Optional[str] = None


@pytest.fixture
def memory_logger() -> tuple[logging.Logger, io.StringIO]:
    """Provides an isolated in-memory logger to verify zero-credential logging."""
    stream = io.StringIO()
    logger = logging.getLogger("TestGatewayLogger")
    logger.handlers.clear()
    handler = logging.StreamHandler(stream)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    return logger, stream


class TestDestinationValidation:
    """Requirement 4: Allow only exact hostname lunai.dpdns.org. Reject all others."""

    def test_permitted_exact_hostname(self) -> None:
        ok, _ = validate_destination("lunai.dpdns.org", port=80)
        assert ok is True

        ok, _ = validate_destination("lunai.dpdns.org", port=443)
        assert ok is True

        # Case-insensitivity per DNS RFCs
        ok, _ = validate_destination("LUNAI.DPDNS.ORG", port=80)
        assert ok is True

        ok, _ = validate_destination("LuNaI.dPdNs.OrG", port=443)
        assert ok is True

        # With port suffix in string
        ok, _ = validate_destination("lunai.dpdns.org:80")
        assert ok is True

        ok, _ = validate_destination("lunai.dpdns.org:443")
        assert ok is True

    def test_reject_subdomains(self) -> None:
        """Requirement 4: Reject subdomains."""
        subdomains = [
            "api.lunai.dpdns.org",
            "sub.lunai.dpdns.org",
            "admin.lunai.dpdns.org",
            "dev.lunai.dpdns.org",
            "staging.lunai.dpdns.org",
            "internal.api.lunai.dpdns.org",
            "test-lunai.dpdns.org",  # Not exact match
        ]
        for sub in subdomains:
            ok, reason = validate_destination(sub, port=80)
            assert ok is False, f"Subdomain '{sub}' should have been rejected"
            assert "prohibited" in reason.lower()

    def test_reject_ip_literals(self) -> None:
        """Requirement 4: Reject IP literals (both IPv4 and IPv6)."""
        ips = [
            "127.0.0.1",
            "127.0.0.1:80",
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "104.21.5.1",  # Target resolution IP
            "0.0.0.0",
            "::1",
            "[::1]",
            "[::1]:443",
            "[2001:db8::1]:80",
        ]
        for ip in ips:
            ok, reason = validate_destination(ip, port=80)
            assert ok is False, f"IP literal '{ip}' should have been rejected"
            assert "prohibited" in reason.lower()

    def test_reject_alternate_and_unrelated_hosts(self) -> None:
        """Requirement 4: Reject parent domain, alternate hostnames, and external sites."""
        unrelated = [
            "dpdns.org",  # Parent domain
            "lunai.dpdns.com",  # Wrong TLD
            "lunai-dpdns.org",  # Typosquat
            "lunai.dpdns.org.attacker.com",  # Domain appending
            "attacker.com",
            "google.com",
            "localhost",
            "example.org",
        ]
        for host in unrelated:
            ok, reason = validate_destination(host, port=80)
            assert ok is False, f"Host '{host}' should have been rejected"
            assert "prohibited" in reason.lower()

    def test_reject_unpermitted_ports(self) -> None:
        """Permit only standard web ports (80, 443)."""
        bad_ports = [8080, 8443, 22, 21, 3306, 5432, 8000]
        for p in bad_ports:
            ok, reason = validate_destination("lunai.dpdns.org", port=p)
            assert ok is False
            assert "port" in reason.lower()

    def test_reject_empty_or_malformed(self) -> None:
        ok, _ = validate_destination("")
        assert ok is False

        ok, _ = validate_destination(None)
        assert ok is False


class TestHttpsConnectValidation:
    """Requirement 5: Validate HTTPS CONNECT destinations and fail closed."""

    def test_connect_permitted_target_succeeds(self, memory_logger: Any) -> None:
        async def _run() -> None:
            logger, _ = memory_logger
            addon = GatewayAddon(logger=logger)

            req = MockRequest(
                method="CONNECT",
                scheme="https",
                host="lunai.dpdns.org",
                port=443,
                pretty_host="lunai.dpdns.org",
            )
            flow = MockFlow(req)

            await addon.http_connect(flow)
            # Permitted CONNECT tunnel: response is NOT intercepted (remains None)
            assert flow.response is None

        asyncio.run(_run())

    def test_connect_unauthorized_destinations_fail_closed_with_403(
        self, memory_logger: Any
    ) -> None:
        async def _run() -> None:
            logger, _ = memory_logger
            addon = GatewayAddon(logger=logger)

            prohibited_destinations = [
                ("api.lunai.dpdns.org", 443),
                ("127.0.0.1", 443),
                ("[::1]", 443),
                ("attacker.com", 443),
                ("dpdns.org", 443),
                ("lunai.dpdns.org", 8080),
            ]

            for dest_host, dest_port in prohibited_destinations:
                req = MockRequest(
                    method="CONNECT",
                    scheme="https",
                    host=dest_host,
                    port=dest_port,
                    pretty_host=dest_host,
                )
                flow = MockFlow(req)

                await addon.http_connect(flow)

                assert flow.response is not None, f"CONNECT to {dest_host} should be intercepted"
                assert flow.response.status_code == 403
                assert flow.response.headers.get("X-Gateway-Policy") in (
                    "CONNECT-Destination-Violation",
                    "DNS-Rebinding-Blocked",
                )
                assert b"403 Forbidden" in flow.response.content

        asyncio.run(_run())


class TestHttpRequestValidation:
    """Requirement 4 & 5: Validate HTTP request destinations and fail closed."""

    def test_http_request_permitted_target(self, memory_logger: Any) -> None:
        async def _run() -> None:
            logger, _ = memory_logger
            addon = GatewayAddon(logger=logger)

            req = MockRequest(
                method="GET",
                scheme="http",
                host="lunai.dpdns.org",
                port=80,
                path="/login",
                headers={"Host": "lunai.dpdns.org"},
            )
            flow = MockFlow(req)

            await addon.request(flow)
            assert flow.response is None, "Permitted request should be forwarded"

        asyncio.run(_run())

    def test_http_request_subdomain_rejected_with_403(self, memory_logger: Any) -> None:
        async def _run() -> None:
            logger, _ = memory_logger
            addon = GatewayAddon(logger=logger)

            req = MockRequest(
                method="GET",
                scheme="http",
                host="sub.lunai.dpdns.org",
                port=80,
                path="/",
                pretty_host="sub.lunai.dpdns.org",
            )
            flow = MockFlow(req)

            await addon.request(flow)
            assert flow.response is not None
            assert flow.response.status_code == 403
            assert b"Forbidden" in flow.response.content

        asyncio.run(_run())

    def test_http_request_ip_literal_rejected_with_403(self, memory_logger: Any) -> None:
        async def _run() -> None:
            logger, _ = memory_logger
            addon = GatewayAddon(logger=logger)

            req = MockRequest(
                method="POST",
                scheme="http",
                host="127.0.0.1",
                port=80,
                path="/api",
                pretty_host="127.0.0.1",
            )
            flow = MockFlow(req)

            await addon.request(flow)
            assert flow.response is not None
            assert flow.response.status_code == 403
            assert flow.response.headers.get("X-Gateway-Policy") == "Destination-Violation"

        asyncio.run(_run())

    def test_host_header_spoofing_rejected_with_403(self, memory_logger: Any) -> None:
        """Reject mismatch when Host header differs from destination or targets unauthorized host."""
        async def _run() -> None:
            logger, _ = memory_logger
            addon = GatewayAddon(logger=logger)

            # Host claims to be lunai.dpdns.org, but Host header is attacker.com
            req = MockRequest(
                method="GET",
                scheme="http",
                host="lunai.dpdns.org",
                port=80,
                path="/",
                pretty_host="lunai.dpdns.org",
                headers={"Host": "attacker.com"},
            )
            flow = MockFlow(req)

            await addon.request(flow)
            assert flow.response is not None
            assert flow.response.status_code == 403
            assert flow.response.headers.get("X-Gateway-Policy") == "Host-Header-Violation"

        asyncio.run(_run())


class TestRateLimiterIntegration:
    """Requirements 2, 3, 9: Rolling 5 req / 60s limit shared across flows."""

    def test_addon_enforces_rolling_rate_limit(self, memory_logger: Any) -> None:
        async def _run() -> None:
            logger, _ = memory_logger
            limiter = RollingWindowLimiter(max_requests=5, window_seconds=60.0)
            addon = GatewayAddon(limiter=limiter, logger=logger)

            # 5 immediate requests succeed without delay
            for i in range(5):
                flow = MockFlow(MockRequest(path=f"/test{i}"))
                await addon.request(flow)
                assert flow.response is None

            assert addon.limiter.window_count == 5

        asyncio.run(_run())

    def test_shared_limiter_across_independent_flows(self, memory_logger: Any) -> None:
        """Requirement 9: Limiter must be shared across all flows handled by gateway."""
        async def _run() -> None:
            logger, _ = memory_logger
            limiter = RollingWindowLimiter(max_requests=3, window_seconds=60.0)
            addon = GatewayAddon(limiter=limiter, logger=logger)

            # Send 3 requests across completely independent flow instances
            f1 = MockFlow(MockRequest(path="/agent1/flow1"))
            f2 = MockFlow(MockRequest(path="/agent2/flow2"))
            f3 = MockFlow(MockRequest(path="/agent3/flow3"))

            await addon.request(f1)
            await addon.request(f2)
            await addon.request(f3)

            assert addon.limiter.window_count == 3
            assert addon.limiter.total_admitted == 3

        asyncio.run(_run())

    def test_fail_closed_on_rate_limiter_error(self, memory_logger: Any) -> None:
        """Requirement 6: Fail closed if rate limiting fails."""
        async def _run() -> None:
            logger, _ = memory_logger

            class BrokenLimiter(RollingWindowLimiter):
                async def acquire_async(self, timeout: Optional[float] = None) -> float:
                    raise RateLimitError("Simulated internal limiter corruption")

            addon = GatewayAddon(limiter=BrokenLimiter(), logger=logger)
            flow = MockFlow(MockRequest(path="/data"))

            await addon.request(flow)

            # Must fail closed with 500, never forwarded
            assert flow.response is not None
            assert flow.response.status_code == 500
            assert flow.response.headers.get("X-Gateway-Policy") == "Limiter-Failure-FailClosed"
            assert b"500 Internal Gateway Error" in flow.response.content

        asyncio.run(_run())


class TestZeroCredentialLogging:
    """Requirement 8: Do not log credentials, cookies, auth headers, bodies, or query params."""

    def test_sensitive_artifacts_are_never_logged(self, memory_logger: Any) -> None:
        async def _run() -> None:
            logger, stream = memory_logger
            addon = GatewayAddon(logger=logger)

            secret_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_payload"
            secret_cookie = "session_id=secret_cookie_val_998877"
            secret_query_val = "SECRET_API_KEY_443322"
            secret_body = b'{"password": "MySuperSecretPassword123!"}'

            req = MockRequest(
                method="POST",
                scheme="http",
                host="lunai.dpdns.org",
                port=80,
                path=f"/api/v1/auth?token={secret_query_val}&debug=1",
                headers={
                    "Host": "lunai.dpdns.org",
                    "Authorization": f"Bearer {secret_token}",
                    "Cookie": secret_cookie,
                    "X-Api-Key": secret_token,
                },
                content=secret_body,
            )
            flow = MockFlow(req)

            await addon.request(flow)

            logged_content = stream.getvalue()

            # Assert zero credentials / PII in log stream
            assert secret_token not in logged_content, "Authorization token leaked in gateway log!"
            assert secret_cookie not in logged_content, "Session cookie leaked in gateway log!"
            assert secret_query_val not in logged_content, "Query parameter value leaked in gateway log!"
            assert "password" not in logged_content, "Request body content leaked in gateway log!"
            assert "MySuperSecretPassword123!" not in logged_content

            # Verify that only sanitized path was logged
            assert "url=http://lunai.dpdns.org/api/v1/auth" in logged_content
            assert "?token=" not in logged_content

        asyncio.run(_run())


class TestAntiBypassAndTamperResistance:
    """Requirement 10: Do not provide a way for Strix agents to modify or bypass gateway."""

    def test_agent_bypass_headers_are_stripped(self, memory_logger: Any) -> None:
        async def _run() -> None:
            logger, _ = memory_logger
            limiter = RollingWindowLimiter(max_requests=1, window_seconds=60.0)
            addon = GatewayAddon(limiter=limiter, logger=logger)

            req = MockRequest(
                path="/search",
                headers={
                    "Host": "lunai.dpdns.org",
                    "X-Bypass-Rate-Limit": "true",
                    "X-Gateway-Override": "admin",
                },
            )
            flow = MockFlow(req)

            await addon.request(flow)

            # Bypass headers must be stripped from the request
            assert "X-Bypass-Rate-Limit" not in flow.request.headers
            assert "X-Gateway-Override" not in flow.request.headers
            assert addon.limiter.total_admitted == 1

        asyncio.run(_run())

    def test_configuration_immutability(self) -> None:
        addon = GatewayAddon()

        # Permitted host is read-only property
        with pytest.raises(AttributeError):
            addon.permitted_host = "attacker.com"  # type: ignore

        with pytest.raises(AttributeError):
            addon.permitted_ports = (8080,)  # type: ignore


class TestNoRetries:
    """Requirement 7: Never retry requests automatically."""

    def test_error_hook_logs_without_retrying(self, memory_logger: Any) -> None:
        logger, stream = memory_logger
        addon = GatewayAddon(logger=logger)

        flow = MockFlow(MockRequest())
        flow.error = "Connection reset by peer"

        addon.error(flow)

        logs = stream.getvalue()
        assert "FLOW_ERROR_NO_RETRY" in logs
        assert "Connection reset by peer" in logs


class TestProtocolBypassDefense:
    """Correction 1: Reject WebSocket upgrades, raw TCP, and ensure conservative CONNECT counting."""

    def test_websocket_upgrade_rejected_with_403(self, memory_logger: Any) -> None:
        async def _run() -> None:
            logger, _ = memory_logger
            addon = GatewayAddon(logger=logger)

            req = MockRequest(
                method="GET",
                path="/ws/chat",
                headers={
                    "Host": "lunai.dpdns.org",
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                },
            )
            flow = MockFlow(req)

            await addon.request(flow)
            assert flow.response is not None
            assert flow.response.status_code == 403
            assert flow.response.headers.get("X-Gateway-Policy") == "WebSocket-Prohibited"
            assert b"WebSocket upgrades are prohibited" in flow.response.content

        asyncio.run(_run())

    def test_tcp_start_kills_opaque_tunnel_flow(self, memory_logger: Any) -> None:
        logger, stream = memory_logger
        addon = GatewayAddon(logger=logger)

        class MockTcpFlow:
            def __init__(self) -> None:
                self.killed = False

            def kill(self) -> None:
                self.killed = True

        flow = MockTcpFlow()
        addon.tcp_start(flow)
        assert flow.killed is True
        assert "Opaque TCP passthrough is strictly prohibited" in stream.getvalue()

    def test_websocket_start_kills_websocket_stream(self, memory_logger: Any) -> None:
        logger, stream = memory_logger
        addon = GatewayAddon(logger=logger)

        class MockWsFlow:
            def __init__(self) -> None:
                self.killed = False

            def kill(self) -> None:
                self.killed = True

        flow = MockWsFlow()
        addon.websocket_start(flow)
        assert flow.killed is True
        assert "WebSocket communication is strictly prohibited" in stream.getvalue()

    def test_udp_start_kills_udp_flow(self, memory_logger: Any) -> None:
        logger, stream = memory_logger
        addon = GatewayAddon(logger=logger)

        class MockUdpFlow:
            def __init__(self) -> None:
                self.killed = False

            def kill(self) -> None:
                self.killed = True

        flow = MockUdpFlow()
        addon.udp_start(flow)
        assert flow.killed is True

    def test_connect_consumes_rate_limit_token(self, memory_logger: Any) -> None:
        async def _run() -> None:
            logger, _ = memory_logger
            limiter = RollingWindowLimiter(max_requests=5, window_seconds=60.0)
            addon = GatewayAddon(limiter=limiter, logger=logger)

            req = MockRequest(method="CONNECT", port=443)
            flow = MockFlow(req)

            assert addon.limiter.window_count == 0
            await addon.http_connect(flow)
            # CONNECT must have consumed 1 admission token
            assert addon.limiter.window_count == 1
            assert flow.response is None

        asyncio.run(_run())


class TestDnsRebindingProtection:
    """Correction 3: Reject loopback, private, mixed IP sets, and guard against TOCTOU gaps."""

    def test_public_ip_resolution_permitted(self, memory_logger: Any) -> None:
        async def _run() -> None:
            logger, _ = memory_logger
            # Custom resolver returning legitimate public IP
            resolver = lambda host: ["93.184.216.34", "93.184.216.35"]
            addon = GatewayAddon(dns_resolver=resolver, logger=logger)

            req = MockRequest(path="/status")
            flow = MockFlow(req)

            await addon.request(flow)
            assert flow.response is None

        asyncio.run(_run())

    def test_private_ip_resolution_rejected_with_403(self, memory_logger: Any) -> None:
        async def _run() -> None:
            logger, _ = memory_logger
            bad_ips = [
                ["127.0.0.1"],
                ["10.0.0.1"],
                ["192.168.1.100"],
                ["172.16.0.1"],
                ["169.254.169.254"],
                ["::1"],
                ["0.0.0.0"],
            ]
            for ip_set in bad_ips:
                addon = GatewayAddon(dns_resolver=lambda h, ips=ip_set: ips, logger=logger)
                req = MockRequest(path="/test")
                flow = MockFlow(req)

                await addon.request(flow)
                assert flow.response is not None
                assert flow.response.status_code == 403
                assert flow.response.headers.get("X-Gateway-Policy") == "DNS-Rebinding-Blocked"

        asyncio.run(_run())

    def test_mixed_ip_resolution_rejected(self, memory_logger: Any) -> None:
        """Requirement 3: DNS returning mixed public and private address sets must fail closed."""
        async def _run() -> None:
            logger, _ = memory_logger
            # Mixed set: 1 valid public IP + 1 internal loopback/private IP
            mixed_ips = ["93.184.216.34", "127.0.0.1"]
            addon = GatewayAddon(dns_resolver=lambda h: mixed_ips, logger=logger)

            req = MockRequest(path="/mixed")
            flow = MockFlow(req)

            await addon.request(flow)
            assert flow.response is not None
            assert flow.response.status_code == 403
            assert flow.response.headers.get("X-Gateway-Policy") == "DNS-Rebinding-Blocked"

        asyncio.run(_run())

    def test_toctou_server_connect_blocks_private_ip(self, memory_logger: Any) -> None:
        logger, _ = memory_logger
        addon = GatewayAddon(logger=logger)

        class MockServerConn:
            def __init__(self, ip: str, port: int = 443) -> None:
                self.address = (ip, port)
                self.error = None

        class MockServerConnectData:
            def __init__(self, ip: str) -> None:
                self.server = MockServerConn(ip)
                self.killed = False

            def kill(self) -> None:
                self.killed = True

        data = MockServerConnectData("10.0.0.5")
        addon.server_connect(data)
        assert data.server.error is not None
        assert "prohibited" in data.server.error.lower()

    def test_toctou_server_connect_allows_public_ip(self, memory_logger: Any) -> None:
        logger, _ = memory_logger
        addon = GatewayAddon(logger=logger)

        class MockServerConn:
            def __init__(self, ip: str, port: int = 443) -> None:
                self.address = (ip, port)
                self.error = None

        class MockServerConnectData:
            def __init__(self, ip: str) -> None:
                self.server = MockServerConn(ip)

        data = MockServerConnectData("93.184.216.34")
        addon.server_connect(data)
        assert data.server.error is None


class TestBoundedQueueTimeout:
    """Correction 5: Bounded queue wait timeout returning fail-closed HTTP 504 Gateway Timeout."""

    def test_queue_timeout_fails_closed_with_504(self, memory_logger: Any) -> None:
        async def _run() -> None:
            logger, stream = memory_logger
            # Queue timeout of 0.01 seconds
            limiter = RollingWindowLimiter(max_requests=1, window_seconds=60.0)
            addon = GatewayAddon(limiter=limiter, queue_timeout=0.01, logger=logger)

            # 1st request succeeds immediately
            f1 = MockFlow(MockRequest(path="/req1"))
            await addon.request(f1)
            assert f1.response is None

            # 2nd request requires ~60s wait, but queue_timeout is 0.01s -> must return 504
            f2 = MockFlow(MockRequest(path="/req2"))
            await addon.request(f2)
            assert f2.response is not None
            assert f2.response.status_code == 504
            assert f2.response.headers.get("X-Gateway-Policy") == "Queue-Timeout-FailClosed"
            assert b"504 Gateway Timeout" in f2.response.content
            assert "TIMEOUT" in stream.getvalue()

        asyncio.run(_run())
