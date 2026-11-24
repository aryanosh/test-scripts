# Strix Traffic-Control Gateway Container
#
# Architecture:
#   Strix sandbox -> Caido -> mitmproxy upstream gateway -> permitted destination
#
# Security Controls Enforced:
# 1. Global rolling-window rate limit (<= 5 HTTP requests per 60 seconds).
# 2. Strict exact-hostname allowlisting: lunai.dpdns.org only.
# 3. HTTP requests and HTTPS CONNECT inspection with fail-closed security.
# 4. Zero-credential / zero-PII logging (no cookies, tokens, query params, or bodies).
# 5. Non-root execution with hardened, read-only filesystem permissions.
# 6. Tamper-resistant: agents cannot modify or bypass gateway rules.

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create unprivileged system group and user, along with runtime writable directories
RUN groupadd -g 1000 gateway && \
    useradd -u 1000 -g gateway -m -s /bin/bash gatewayuser && \
    mkdir -p /home/gatewayuser/.mitmproxy /app/data && \
    chown -R gatewayuser:gateway /home/gatewayuser/.mitmproxy /app/data && \
    chmod 700 /home/gatewayuser/.mitmproxy && \
    chmod 750 /app/data

WORKDIR /app

# Install dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy gateway components
COPY limiter.py /app/gateway/limiter.py
COPY mitm_addon.py /app/gateway/mitm_addon.py

# Ensure gateway package is discoverable and persistent state path is configured
ENV PYTHONPATH=/app \
    GATEWAY_DB_PATH=/app/data/gateway_limiter.db

# Harden file permissions: root owns application code; gatewayuser has read-only access
RUN chown -R root:root /app && \
    chown -R gatewayuser:gateway /app/data && \
    chmod -R 755 /app && \
    chmod -R 750 /app/data

# Declare volumes for persistent state and CA cert generation
VOLUME ["/home/gatewayuser/.mitmproxy", "/app/data"]

# Switch to unprivileged user
USER gatewayuser

# Expose upstream proxy port
EXPOSE 8080

# Health check to ensure mitmproxy is accepting connections
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import socket; s = socket.socket(); s.connect(('127.0.0.1', 8080)); s.close()" || exit 1

ENTRYPOINT ["mitmdump"]
CMD [ \
    "-s", "/app/gateway/mitm_addon.py", \
    "--listen-host", "0.0.0.0", \
    "--listen-port", "8080", \
    "--set", "flow_detail=0", \
    "--set", "connection_strategy=lazy" \
]
