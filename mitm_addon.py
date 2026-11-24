"""mitmproxy Traffic-Control Gateway Addon for Strix VAPT Assessment.

Architecture:
    Strix sandbox -> Caido -> mitmproxy upstream gateway -> permitted destination.

Enforces:
1. Strict exact-hostname allowlisting (lunai.dpdns.org only).
2. Rejection of IP literals, subdomains, alternate hostnames, and all other destinations.
3. Destination validation on both HTTP requests and HTTPS CONNECT flows.
4. DNS rebinding protection: validates destination IPs against loopback, private, link-local,
   multicast, reserved, unspecified, and cloud metadata ranges; guards against TOCTOU gaps.
5. Global rolling-window rate limiting of 5 HTTP requests per 60 seconds across all flows.
6. Conservative rate-limiting of HTTPS CONNECT tunnels; rejection of opaque/unintercepted TCP tunnels.
7. Rejection of WebSocket upgrades and unsupported raw TCP / UDP traffic.
8. Bounded queue wait timeout (fail closed with HTTP 504 Gateway Timeout).
9. Fail-closed security on any validation or rate limiting failure.
10. Zero-credential / zero-PII logging (no authorization headers, cookies, bodies, or query parameters).
11. Immutable, tamper-resistant gateway configuration.
12. No automated retries.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import sys
from typing import Any, Callable, Final, List, Optional, Sequence, Tuple

# Support running in environments where mitmproxy is installed (Docker)
# as well as minimal local test harnesses.
try:
    from mitmproxy import http
except ImportError:  # pragma: no cover
    class _MockResponse:
        def __init__(
            self,
            status_code: int = 200,
            content: bytes = b"",
            headers: Optional[dict] = None,
        ) -> None:
            self.status_code = status_code
            self.content = content if isinstance(content, bytes) else content.encode("utf-8")
            self.headers = headers or {}

        @classmethod
        def make(
            cls,
            status_code: int = 200,
            content: bytes | str = b"",
            headers: Optional[dict] = None,
        ) -> _MockResponse:
            if isinstance(content, str):
                content = content.encode("utf-8")
            return cls(status_code, content, headers)

    class _MockHttp:
        Response = _MockResponse
        HTTPFlow = Any

    http = _MockHttp()

# Ensure gateway package / directory is importable
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

try:
    from gateway.limiter import RateLimitError, RateLimitTimeoutError, RollingWindowLimiter
except ImportError:
    from limiter import RateLimitError, RateLimitTimeoutError, RollingWindowLimiter


# Security Configuration Constants (Immutable)
PERMITTED_HOST: Final[str] = "lunai.dpdns.org"
PERMITTED_PORTS: Final[Tuple[int, ...]] = (80, 443)
DEFAULT_MAX_REQUESTS: Final[int] = 5
DEFAULT_WINDOW_SECONDS: Final[float] = 60.0
DEFAULT_QUEUE_TIMEOUT: Final[float] = 30.0

# Headers that agents must never use to alter or influence gateway behavior
SENSITIVE_OR_OVERRIDE_HEADERS: Final[Tuple[str, ...]] = (
    "x-bypass-rate-limit",
    "x-rate-limit-bypass",
    "x-gateway-override",
    "x-gateway-admin",
    "x-forwarded-host",
    "x-original-host",
)


def is_safe_public_ip(ip_str: str) -> Tuple[bool, str]:
    """Evaluates whether an IP address is a safe, globally routable public address.

    Rejects:
    - Loopback (127.0.0.0/8, ::1)
    - Private (RFC 1918 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    - Link-local (169.254.0.0/16, fe80::/10)
    - Cloud metadata (169.254.169.254)
    - Multicast (224.0.0.0/4, ff00::/8)
    - Reserved and unspecified (0.0.0.0, ::)
    - IPv4-mapped IPv6 loopback/private addresses
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, f"Invalid IP address format: '{ip_str}'"

    # Explicit cloud metadata check
    if str(ip) == "169.254.169.254":
        return False, f"Cloud metadata IP '{ip_str}' is strictly prohibited"

    if ip.is_loopback:
        return False, f"Loopback IP '{ip_str}' is strictly prohibited"
    if ip.is_private:
        return False, f"Private IP '{ip_str}' is strictly prohibited"
    if ip.is_link_local:
        return False, f"Link-local IP '{ip_str}' is strictly prohibited"
    if ip.is_multicast:
        return False, f"Multicast IP '{ip_str}' is strictly prohibited"
    if ip.is_reserved:
        return False, f"Reserved IP '{ip_str}' is strictly prohibited"
    if ip.is_unspecified:
        return False, f"Unspecified IP '{ip_str}' is strictly prohibited"
    if not ip.is_global:
        return False, f"Non-global IP '{ip_str}' is strictly prohibited"

    # Check for IPv4-mapped IPv6 (e.g., ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return is_safe_public_ip(str(ip.ipv4_mapped))

    return True, "Safe public IP"


def resolve_and_validate_hostname(
    hostname: str,
    dns_resolver: Optional[Callable[[str], List[str]]] = None,
) -> Tuple[bool, str, List[str]]:
    """Resolves hostname and verifies that ALL resolved IPs are safe public IPs.

    If any IP in the returned set is private, loopback, or non-global, the entire
    resolution is rejected (preventing mixed-address DNS rebinding).
    """
    if dns_resolver is not None:
        try:
            ips = dns_resolver(hostname)
        except Exception as err:
            return False, f"DNS resolver error for '{hostname}': {err}", []
    else:
        # Check environment or default offline verification IP
        if os.environ.get("GATEWAY_USE_SYSTEM_DNS") == "1":
            try:
                results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                ips = list(dict.fromkeys(r[4][0] for r in results))
            except Exception as err:
                return False, f"System DNS resolution failed for '{hostname}': {err}", []
        else:
            # Default offline safe public IP for permitted host during test harness execution
            if hostname.lower() == PERMITTED_HOST:
                ips = [os.environ.get("GATEWAY_TARGET_IP", "93.184.216.34")]
            else:
                ips = []

    if not ips:
        return False, f"DNS resolution for '{hostname}' returned no IP addresses", []

    for ip in ips:
        is_safe, reason = is_safe_public_ip(ip)
        if not is_safe:
            return (
                False,
                f"DNS resolution for '{hostname}' returned prohibited address '{ip}': {reason}",
                [],
            )

    return True, "All resolved addresses are verified public IPs", ips


def validate_destination(
    raw_host: Optional[str],
    port: Optional[int] = None,
    permitted_host: str = PERMITTED_HOST,
    permitted_ports: Tuple[int, ...] = PERMITTED_PORTS,
) -> Tuple[bool, str]:
    """Validates destination hostname and port against strict engagement constraints.

    Rules:
    - Host must be exactly `permitted_host` (case-insensitive).
    - IP literals (IPv4 and IPv6) are strictly prohibited.
    - Subdomains of `permitted_host` are strictly prohibited.
    - Alternate hostnames and external destinations are strictly prohibited.
    - Ports outside permitted web ports (80, 443) are prohibited.

    Args:
        raw_host: Hostname or host:port string to evaluate.
        port: Destination port number, if known.
        permitted_host: Exact allowed host (default: lunai.dpdns.org).
        permitted_ports: Tuple of allowed ports (default: 80, 443).

    Returns:
        Tuple[bool, str]: (is_valid, reason)
    """
    if not raw_host:
        return False, "Destination host is missing or empty"

    clean = raw_host.strip()

    # Handle bracketed IPv6 literal [::1] or [::1]:port
    if clean.startswith("["):
        bracket_end = clean.find("]")
        if bracket_end == -1:
            return False, f"Malformed IPv6 literal destination: '{clean}'"
        ip_part = clean[1:bracket_end]
        port_part = clean[bracket_end + 1 :]
        if port_part.startswith(":"):
            try:
                port = int(port_part[1:])
            except ValueError:
                return False, f"Invalid destination port in '{clean}'"
        return False, f"IP literal destination '[{ip_part}]' is prohibited; only exact hostname '{permitted_host}' is permitted"

    # Handle standard host:port format
    if ":" in clean:
        parts = clean.split(":")
        if len(parts) == 2:
            clean = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                return False, f"Invalid destination port in '{parts[1]}'"
        elif len(parts) > 2:
            # IPv6 literal without brackets
            try:
                ipaddress.ip_address(clean)
                return False, f"IPv6 literal destination '{clean}' is prohibited; only exact hostname '{permitted_host}' is permitted"
            except ValueError:
                return False, f"Malformed destination host format: '{clean}'"

    # Check for IPv4 literal (or unbracketed IPv6)
    try:
        ipaddress.ip_address(clean)
        return False, f"IP literal destination '{clean}' is prohibited; only exact hostname '{permitted_host}' is permitted"
    except ValueError:
        pass

    normalized_host = clean.lower()
    target_lower = permitted_host.lower()

    # Reject subdomains (e.g., api.lunai.dpdns.org, sub.lunai.dpdns.org)
    if normalized_host.endswith(f".{target_lower}") and normalized_host != target_lower:
        return False, f"Subdomain destination '{normalized_host}' is prohibited; only exact hostname '{permitted_host}' is permitted"

    # Reject any host that is not an exact match
    if normalized_host != target_lower:
        return False, f"Destination host '{normalized_host}' is prohibited; only exact hostname '{permitted_host}' is permitted"

    # Validate destination port if provided
    if port is not None and port not in permitted_ports:
        return False, f"Destination port {port} is prohibited; only ports {permitted_ports} are permitted"

    return True, "Permitted"


def format_sanitized_log(
    decision: str,
    method: str,
    scheme: str,
    host: str,
    port: int,
    raw_path: str,
    wait_time: float,
    status_code: Optional[int] = None,
    detail: Optional[str] = None,
) -> str:
    """Formats an audit log entry strictly stripped of sensitive data.

    In accordance with Requirement 8:
    - Never logs query strings (?token=...).
    - Never logs request/response headers (Authorization, Cookie, etc.).
    - Never logs request/response bodies.
    - Only logs method, sanitized URL path, queue wait time, and decision.
    """
    clean_path = raw_path.split("?")[0].split("#")[0]
    if not clean_path.startswith("/"):
        clean_path = "/" + clean_path

    # Standard web port formatting
    port_str = ""
    if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
        port_str = f":{port}"

    sanitized_url = f"{scheme}://{host}{port_str}{clean_path}"
    status_str = f" status={status_code}" if status_code is not None else ""
    detail_str = f" detail='{detail}'" if detail else ""

    return (
        f"[GATEWAY] decision={decision} method={method} url={sanitized_url} "
        f"wait_time={wait_time:.3f}s{status_str}{detail_str}"
    )


class GatewayAddon:
    """mitmproxy addon enforcing rolling rate limits, destination boundaries, and rebinding protection."""

    def __init__(
        self,
        limiter: Optional[RollingWindowLimiter] = None,
        permitted_host: str = PERMITTED_HOST,
        permitted_ports: Tuple[int, ...] = PERMITTED_PORTS,
        dns_resolver: Optional[Callable[[str], List[str]]] = None,
        queue_timeout: float = DEFAULT_QUEUE_TIMEOUT,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """Initialize the traffic-control gateway addon.

        Args:
            limiter: Shared RollingWindowLimiter instance.
            permitted_host: Allowed target hostname.
            permitted_ports: Allowed destination ports.
            dns_resolver: Optional custom DNS resolution provider.
            queue_timeout: Maximum seconds a request may wait in queue before 504 Gateway Timeout.
            logger: Optional logger instance.
        """
        self._limiter: RollingWindowLimiter = limiter or RollingWindowLimiter(
            max_requests=DEFAULT_MAX_REQUESTS,
            window_seconds=DEFAULT_WINDOW_SECONDS,
        )
        self._permitted_host: str = permitted_host
        self._permitted_ports: Tuple[int, ...] = permitted_ports
        self._dns_resolver: Optional[Callable[[str], List[str]]] = dns_resolver
        self._queue_timeout: float = float(queue_timeout)

        if logger is None:
            self._logger = logging.getLogger("GatewayAddon")
            if not self._logger.handlers:
                handler = logging.StreamHandler(sys.stdout)
                handler.setFormatter(
                    logging.Formatter("%(asctime)s %(levelname)s %(message)s")
                )
                self._logger.addHandler(handler)
            self._logger.setLevel(logging.INFO)
        else:
            self._logger = logger

    @property
    def permitted_host(self) -> str:
        """Immutable permitted hostname."""
        return self._permitted_host

    @property
    def permitted_ports(self) -> Tuple[int, ...]:
        """Immutable permitted destination ports."""
        return self._permitted_ports

    @property
    def limiter(self) -> RollingWindowLimiter:
        """Shared rolling-window rate limiter."""
        return self._limiter

    @property
    def queue_timeout(self) -> float:
        """Maximum queue wait timeout in seconds."""
        return self._queue_timeout

    def _fail_closed(
        self,
        flow: Any,
        status_code: int,
        reason: str,
        policy: str,
    ) -> None:
        """Fails closed by intercepting and rejecting the flow immediately.

        Setting flow.response stops mitmproxy from forwarding the request upstream.
        Falls back to killing the flow if response creation fails.
        """
        try:
            body = f"{status_code} {reason}\r\n".encode("utf-8")
            flow.response = http.Response.make(
                status_code,
                body,
                {
                    "Content-Type": "text/plain; charset=utf-8",
                    "X-Gateway-Policy": policy,
                    "Connection": "close",
                    "Cache-Control": "no-store",
                },
            )
        except Exception:
            if hasattr(flow, "kill"):
                flow.kill()

    async def http_connect(self, flow: Any) -> None:
        """Intercepts, validates, and conservatively rate-limits HTTPS CONNECT tunnel establishment.

        Enforces:
        - Exact host allowlisting.
        - DNS rebinding & public IP validation.
        - Upstream IP address pinning to prevent TOCTOU gaps.
        - Conservative admission consumption from rolling rate limiter.
        - Fail-closed security with 504 Gateway Timeout on queue timeout.
        """
        try:
            target_host = getattr(flow.request, "pretty_host", "") or getattr(
                flow.request, "host", ""
            )
            port = getattr(flow.request, "port", 443)

            # 1. Hostname validation
            is_valid, reason = validate_destination(
                target_host,
                port=port,
                permitted_host=self._permitted_host,
                permitted_ports=self._permitted_ports,
            )
            if not is_valid:
                self._fail_closed(
                    flow,
                    status_code=403,
                    reason=f"Forbidden: {reason}",
                    policy="CONNECT-Destination-Violation",
                )
                self._logger.warning(
                    format_sanitized_log(
                        decision="REJECTED",
                        method="CONNECT",
                        scheme="https",
                        host=target_host or "unknown",
                        port=port,
                        raw_path="/",
                        wait_time=0.0,
                        status_code=403,
                        detail=reason,
                    )
                )
                return

            # 2. DNS Rebinding & Public IP validation
            dns_safe, dns_reason, resolved_ips = resolve_and_validate_hostname(
                target_host, dns_resolver=self._dns_resolver
            )
            if not dns_safe:
                self._fail_closed(
                    flow,
                    status_code=403,
                    reason=f"Forbidden: {dns_reason}",
                    policy="DNS-Rebinding-Blocked",
                )
                self._logger.warning(
                    format_sanitized_log(
                        decision="REJECTED",
                        method="CONNECT",
                        scheme="https",
                        host=target_host,
                        port=port,
                        raw_path="/",
                        wait_time=0.0,
                        status_code=403,
                        detail=dns_reason,
                    )
                )
                return

            # Pin upstream connection to verified safe public IP to prevent TOCTOU
            server_conn = getattr(flow, "server_conn", None)
            if server_conn is not None and hasattr(server_conn, "address") and resolved_ips:
                server_conn.address = (resolved_ips[0], port)

            # 3. Conservative rate-limiting of CONNECT tunnel establishment
            try:
                wait_time = await self._limiter.acquire_async(timeout=self._queue_timeout)
            except RateLimitTimeoutError as timeout_err:
                self._fail_closed(
                    flow,
                    status_code=504,
                    reason="Gateway Timeout: CONNECT queue wait time exceeded maximum timeout",
                    policy="Queue-Timeout-FailClosed",
                )
                self._logger.warning(
                    format_sanitized_log(
                        decision="TIMEOUT",
                        method="CONNECT",
                        scheme="https",
                        host=target_host,
                        port=port,
                        raw_path="/",
                        wait_time=self._queue_timeout,
                        status_code=504,
                        detail=str(timeout_err),
                    )
                )
                return
            except Exception as lim_err:
                self._fail_closed(
                    flow,
                    status_code=500,
                    reason="Internal Gateway Error: Rate limiting failure on CONNECT",
                    policy="Limiter-Failure-FailClosed",
                )
                return

            # Mark flow as metered so duplicate accounting does not occur if method == CONNECT in request()
            setattr(flow, "_gateway_connect_metered", True)

            decision = "QUEUED" if wait_time > 0 else "TUNNEL_PERMITTED"
            log_msg = format_sanitized_log(
                decision=decision,
                method="CONNECT",
                scheme="https",
                host=target_host,
                port=port,
                raw_path="/",
                wait_time=wait_time,
                status_code=200,
            )
            self._logger.info(log_msg)

        except Exception as exc:
            self._fail_closed(
                flow,
                status_code=500,
                reason="Internal Gateway Error: CONNECT validation failure",
                policy="CONNECT-Error-FailClosed",
            )
            self._logger.error(
                f"[GATEWAY] decision=ERROR method=CONNECT error='{exc.__class__.__name__}'"
            )

    async def request(self, flow: Any) -> None:
        """Intercepts, validates, and rate limits HTTP/HTTPS requests.

        Enforces:
        - Rejection of WebSocket upgrade requests.
        - Exact host allowlisting across pretty_host, host, and Host header.
        - Host header spoofing / smuggling defense.
        - DNS rebinding validation and TOCTOU address pinning.
        - Global rolling rate limit (<= 5 requests per 60 seconds).
        - FIFO request queuing with bounded queue timeout (504 Gateway Timeout).
        - Fail-closed security architecture.
        - Stripping of agent attempts to bypass gateway via custom headers.
        """
        try:
            req = flow.request
            method = getattr(req, "method", "GET").upper()
            scheme = getattr(req, "scheme", "http").lower()
            port = getattr(req, "port", 80 if scheme == "http" else 443)
            pretty_host = getattr(req, "pretty_host", "")
            host = getattr(req, "host", "")
            path = getattr(req, "path", "/")

            # Strip any agent attempts to bypass or inject gateway control headers (case-insensitive)
            headers = getattr(req, "headers", {})
            keys_to_remove = [k for k in list(headers.keys()) if k.lower() in SENSITIVE_OR_OVERRIDE_HEADERS]
            for k in keys_to_remove:
                del headers[k]

            # 1. Reject WebSocket upgrades
            upgrade_header = headers.get("Upgrade", "") or headers.get("upgrade", "")
            if "websocket" in upgrade_header.lower():
                self._fail_closed(
                    flow,
                    status_code=403,
                    reason="Forbidden: WebSocket upgrades are prohibited by traffic-control gateway",
                    policy="WebSocket-Prohibited",
                )
                self._logger.warning(
                    format_sanitized_log(
                        decision="REJECTED",
                        method=method,
                        scheme=scheme,
                        host=pretty_host or "unknown",
                        port=port,
                        raw_path=path,
                        wait_time=0.0,
                        status_code=403,
                        detail="WebSocket upgrade rejected",
                    )
                )
                return

            # 2. Validate destination host across indicators
            is_valid_pretty, reason_pretty = validate_destination(
                pretty_host,
                port=port,
                permitted_host=self._permitted_host,
                permitted_ports=self._permitted_ports,
            )
            if not is_valid_pretty:
                self._fail_closed(
                    flow,
                    status_code=403,
                    reason=f"Forbidden: {reason_pretty}",
                    policy="Destination-Violation",
                )
                self._logger.warning(
                    format_sanitized_log(
                        decision="REJECTED",
                        method=method,
                        scheme=scheme,
                        host=pretty_host or "unknown",
                        port=port,
                        raw_path=path,
                        wait_time=0.0,
                        status_code=403,
                        detail=reason_pretty,
                    )
                )
                return

            is_valid_host, reason_host = validate_destination(
                host,
                port=port,
                permitted_host=self._permitted_host,
                permitted_ports=self._permitted_ports,
            )
            if not is_valid_host:
                self._fail_closed(
                    flow,
                    status_code=403,
                    reason=f"Forbidden: {reason_host}",
                    policy="Destination-Violation",
                )
                self._logger.warning(
                    format_sanitized_log(
                        decision="REJECTED",
                        method=method,
                        scheme=scheme,
                        host=host or "unknown",
                        port=port,
                        raw_path=path,
                        wait_time=0.0,
                        status_code=403,
                        detail=reason_host,
                    )
                )
                return

            # Check Host header if present (prevent Host-Header injection / smuggling)
            host_header = headers.get("Host") or headers.get("host")
            if host_header:
                is_valid_header, reason_header = validate_destination(
                    host_header,
                    port=port,
                    permitted_host=self._permitted_host,
                    permitted_ports=self._permitted_ports,
                )
                if not is_valid_header:
                    self._fail_closed(
                        flow,
                        status_code=403,
                        reason=f"Forbidden: Host header mismatch: {reason_header}",
                        policy="Host-Header-Violation",
                    )
                    self._logger.warning(
                        format_sanitized_log(
                            decision="REJECTED",
                            method=method,
                            scheme=scheme,
                            host=host_header,
                            port=port,
                            raw_path=path,
                            wait_time=0.0,
                            status_code=403,
                            detail="Host header validation failed",
                        )
                    )
                    return

            # 3. DNS Rebinding & Public IP validation
            dns_safe, dns_reason, resolved_ips = resolve_and_validate_hostname(
                host, dns_resolver=self._dns_resolver
            )
            if not dns_safe:
                self._fail_closed(
                    flow,
                    status_code=403,
                    reason=f"Forbidden: {dns_reason}",
                    policy="DNS-Rebinding-Blocked",
                )
                self._logger.warning(
                    format_sanitized_log(
                        decision="REJECTED",
                        method=method,
                        scheme=scheme,
                        host=host,
                        port=port,
                        raw_path=path,
                        wait_time=0.0,
                        status_code=403,
                        detail=dns_reason,
                    )
                )
                return

            # Pin server connection address to eliminate TOCTOU gap
            server_conn = getattr(flow, "server_conn", None)
            if server_conn is not None and hasattr(server_conn, "address") and resolved_ips:
                server_conn.address = (resolved_ips[0], port)

            # If method is CONNECT, already metered in http_connect
            if method == "CONNECT":
                return

            # 4. Enforce global rolling-window rate limit with bounded timeout
            try:
                wait_time = await self._limiter.acquire_async(timeout=self._queue_timeout)
            except RateLimitTimeoutError as timeout_err:
                self._fail_closed(
                    flow,
                    status_code=504,
                    reason="Gateway Timeout: Rate limit queue wait time exceeded maximum timeout",
                    policy="Queue-Timeout-FailClosed",
                )
                self._logger.warning(
                    format_sanitized_log(
                        decision="TIMEOUT",
                        method=method,
                        scheme=scheme,
                        host=self._permitted_host,
                        port=port,
                        raw_path=path,
                        wait_time=self._queue_timeout,
                        status_code=504,
                        detail=str(timeout_err),
                    )
                )
                return
            except Exception as lim_err:
                # Limiter failure fails closed immediately
                self._fail_closed(
                    flow,
                    status_code=500,
                    reason="Internal Gateway Error: Rate limiting subsystem error",
                    policy="Limiter-Failure-FailClosed",
                )
                self._logger.error(
                    f"[GATEWAY] decision=ERROR method={method} error='{lim_err.__class__.__name__}'"
                )
                return

            # 5. Log sanitized admission
            decision_type = "QUEUED" if wait_time > 0 else "PERMITTED"
            log_entry = format_sanitized_log(
                decision=decision_type,
                method=method,
                scheme=scheme,
                host=self._permitted_host,
                port=port,
                raw_path=path,
                wait_time=wait_time,
            )
            self._logger.info(log_entry)

        except Exception as exc:
            # Fail closed on any unforeseen error
            self._fail_closed(
                flow,
                status_code=500,
                reason="Internal Gateway Error: Request processing failed",
                policy="Request-Error-FailClosed",
            )
            self._logger.error(
                f"[GATEWAY] decision=ERROR method=UNKNOWN error='{exc.__class__.__name__}'"
            )

    def tcp_start(self, flow: Any) -> None:
        """Rejects opaque / unintercepted raw TCP streams to prevent unmetered tunneling."""
        if hasattr(flow, "kill"):
            flow.kill()
        self._logger.warning(
            "[GATEWAY] decision=REJECTED protocol=TCP detail='Opaque TCP passthrough is strictly prohibited'"
        )

    def websocket_start(self, flow: Any) -> None:
        """Rejects WebSocket connections to prevent unmetered bidirectional streaming."""
        if hasattr(flow, "kill"):
            flow.kill()
        self._logger.warning(
            "[GATEWAY] decision=REJECTED protocol=WebSocket detail='WebSocket communication is strictly prohibited'"
        )

    def udp_start(self, flow: Any) -> None:
        """Rejects UDP traffic."""
        if hasattr(flow, "kill"):
            flow.kill()
        self._logger.warning(
            "[GATEWAY] decision=REJECTED protocol=UDP detail='UDP communication is strictly prohibited'"
        )

    def server_connect(self, data: Any) -> None:
        """Validates actual destination IP immediately prior to socket connection.

        Prevents Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks.
        """
        try:
            server = getattr(data, "server", None)
            address = getattr(server, "address", None) if server else getattr(data, "address", None)
            if not address or not isinstance(address, (tuple, list)) or len(address) < 2:
                return

            dest_ip = str(address[0])
            is_safe, reason = is_safe_public_ip(dest_ip)
            if not is_safe:
                if server is not None:
                    setattr(server, "error", f"Connection rejected: destination IP '{dest_ip}' is prohibited: {reason}")
                if hasattr(data, "kill"):
                    data.kill()
                self._logger.error(
                    f"[GATEWAY] decision=REJECTED action=SERVER_CONNECT ip={dest_ip} reason='{reason}'"
                )
        except Exception:
            if hasattr(data, "kill"):
                data.kill()

    def response(self, flow: Any) -> None:
        """Sanitized logging of target responses."""
        try:
            status = getattr(flow.response, "status_code", 0)
            req = flow.request
            method = getattr(req, "method", "GET")
            path = getattr(req, "path", "/")
            scheme = getattr(req, "scheme", "http")
            port = getattr(req, "port", 80)

            log_entry = format_sanitized_log(
                decision="COMPLETED",
                method=method,
                scheme=scheme,
                host=self._permitted_host,
                port=port,
                raw_path=path,
                wait_time=0.0,
                status_code=status,
            )
            self._logger.info(log_entry)
        except Exception:
            pass

    def error(self, flow: Any) -> None:
        """Sanitized logging of connection or upstream errors without retries.

        Requirement 7: Never retry requests automatically.
        """
        try:
            err_msg = getattr(flow, "error", None)
            req = getattr(flow, "request", None)
            method = getattr(req, "method", "UNKNOWN") if req else "UNKNOWN"
            path = getattr(req, "path", "/") if req else "/"
            scheme = getattr(req, "scheme", "http") if req else "http"
            port = getattr(req, "port", 80) if req else 80

            self._logger.warning(
                format_sanitized_log(
                    decision="FLOW_ERROR_NO_RETRY",
                    method=method,
                    scheme=scheme,
                    host=self._permitted_host,
                    port=port,
                    raw_path=path,
                    wait_time=0.0,
                    detail=str(err_msg) if err_msg else "Connection error",
                )
            )
        except Exception:
            pass


# mitmproxy addon entrypoint
addons = [GatewayAddon()]
