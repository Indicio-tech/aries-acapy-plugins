FROM python:3.12-slim-bookworm AS isomdl-build
WORKDIR /build
RUN apt-get update && apt-get install -y curl git build-essential
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

ARG ISOMDL_BRANCH=feature/oid4vp-stateless-verification
RUN git clone https://github.com/Indicio-tech/isomdl-uniffi.git
WORKDIR /build/isomdl-uniffi
RUN git checkout ${ISOMDL_BRANCH}

# Ensure build script is executable
RUN chmod +x python/precommit/build-bindings.sh

WORKDIR /build/isomdl-uniffi/python
# Create package directory and __init__.py to ensure find_packages() works
RUN mkdir -p isomdl_uniffi && \
    echo "try:\n    from .isomdl_uniffi import *\nexcept ImportError:\n    pass" > isomdl_uniffi/__init__.py
RUN pip install build wheel setuptools
RUN python setup.py bdist_wheel || { echo "Build failed"; ls -R /build/isomdl-uniffi; exit 1; }
RUN ls -R /build/isomdl-uniffi/python/dist

FROM python:3.12-slim-bookworm AS base
WORKDIR /usr/src/app

# Install dependencies including git and rust
RUN apt-get update && apt-get install -y curl jq git build-essential && apt-get clean
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Accept build argument for ACA-Py tag
ARG ACAPY_TAG=main

# Clone ACA-Py source at specified tag
RUN git clone https://github.com/openwallet-foundation/acapy.git /usr/src/acapy
WORKDIR /usr/src/acapy
RUN git checkout ${ACAPY_TAG}

# Install ACA-Py using pip (since it doesn't use Poetry)
RUN pip install -e . --no-cache-dir
RUN pip install configargparse

# Setup plugin project structure
WORKDIR /usr/src/app

# Copy the entire plugin source tree
COPY pyproject.toml ./
COPY README.md ./
COPY oid4vc/ oid4vc/
COPY jwt_vc_json/ jwt_vc_json/
COPY mso_mdoc/ mso_mdoc/
COPY sd_jwt_vc/ sd_jwt_vc/

# Install isomdl-uniffi from builder stage
COPY --from=isomdl-build /build/isomdl-uniffi/python/dist/*.whl /tmp/
RUN pip install /tmp/*.whl

# Install the plugin (isomdl-uniffi will be skipped since already installed)
RUN pip install -e . --no-cache-dir

FROM python:3.12-bookworm

WORKDIR /usr/src/app

# Copy the complete environment from base stage
COPY --from=base /usr/src/acapy /usr/src/acapy
COPY --from=base /usr/src/app /usr/src/app

# Install runtime dependencies
RUN apt-get update && apt-get install -y curl jq && apt-get clean

# Copy the entire Python environment from base stage, including site-packages
COPY --from=base /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=base /usr/local/bin /usr/local/bin

# Copy the docker config directory
RUN mkdir -p /usr/src/app/docker
COPY docker/dev.yml /usr/src/app/docker/dev.yml
COPY docker/dev-verifier.yml /usr/src/app/docker/dev-verifier.yml

# Expose ports
EXPOSE 8030 8031 8032

# Add health check
HEALTHCHECK --interval=10s --timeout=5s --retries=5 --start-period=30s \
  CMD curl -f http://localhost:${ACAPY_ADMIN_PORT:-8021}/status/ready || exit 1

# Set working directory and run ACA-Py
WORKDIR /usr/src/acapy
CMD ["python", "-m", "acapy_agent", "start", "--arg-file", "/usr/src/app/docker/dev.yml"]
