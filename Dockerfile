# DGV Verification Kit — Reproducible Container
#
# This Dockerfile provides a one-command, reproducible verification environment
# for the DGV v1.0.0 test suite. Any third party can build this image and run
# the full 60-card suite with identical results.
#
# Substrate:
#   - Base: python:3.10-slim (Debian Bookworm)
#   - Python: 3.10.x
#   - Architecture: linux/amd64 (binaries are pre-compiled for this target)
#   - No network access required after build
#
# Usage:
#   docker build -t dgv-verifier .
#   docker run --rm dgv-verifier
#
# To verify the public registry:
#   docker run --rm dgv-verifier python3 verify_registry.py
#
# To run a single card:
#   docker run --rm dgv-verifier python3 dgv_runner.py --card DGV-TC-001

FROM python:3.10-slim-bookworm

LABEL org.opencontainers.image.title="DGV Verification Kit"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.description="Deterministic & Governance Verified — reproducible verification container"
LABEL org.opencontainers.image.authors="vdmo"
LABEL org.opencontainers.image.source="https://github.com/only-institute/only-dgv-verifier"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir jsonschema

# Copy the verification suite
WORKDIR /dgv

# Copy binaries first (they're architecture-specific)
COPY bin/ ./bin/
RUN chmod +x ./bin/dgv-verifier ./bin/only-gate

# Copy test cards, evidence, and all scripts
COPY test_cards/ ./test_cards/
COPY evidence/ ./evidence/
COPY dgv_runner.py ./dgv_runner.py
COPY dgv_llm_runner.py ./dgv_llm_runner.py
COPY check_passes.py ./check_passes.py
COPY verify_registry.py ./verify_registry.py
COPY registry.json ./registry.json
COPY registry.schema.json ./registry.schema.json
COPY testcards.schema.json ./testcards.schema.json
COPY spec.md ./spec.md
COPY RECEIPT_VERIFICATION.md ./RECEIPT_VERIFICATION.md
COPY requirements.txt ./requirements.txt

# Default command: run the full suite and verify the registry
CMD ["bash", "-c", "python3 dgv_runner.py && echo '---' && python3 verify_registry.py"]
