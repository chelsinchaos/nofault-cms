# Zero-knowledge relay image. Build context = repo root:
#   docker build -f deploy/relay.Dockerfile -t nofault-relay .
# Pin the base by digest in production (see READINESS.md). 3.12-slim shown by tag
# for readability.
FROM python:3.12-slim

# Create an unprivileged user; the relay never needs root.
RUN useradd --create-home --uid 10001 relay

WORKDIR /app

# Install only runtime deps first for layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Install the package itself.
COPY pyproject.toml README.md ./
COPY nofault ./nofault
RUN pip install --no-cache-dir --no-deps .

# Data dir for blobs (mounted as a volume in compose).
RUN mkdir -p /data && chown relay:relay /data
USER relay

ENV NOFAULT_RELAY_STORE=/data \
    NOFAULT_RELAY_PORT=8800

EXPOSE 8800
# Binds 127.0.0.1 inside the container; reachability is via the Tor sidecar only.
CMD ["python", "-m", "uvicorn", "--factory", "nofault.relay._factory:build", \
     "--host", "127.0.0.1", "--port", "8800", "--no-access-log", \
     "--no-server-header"]
