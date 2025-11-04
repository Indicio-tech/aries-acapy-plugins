FROM python:3.12-slim-bookworm AS base
WORKDIR /usr/src/app

# Install dependencies including git
RUN apt-get update && apt-get install -y curl jq git && apt-get clean

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

# Copy and install isomdl-uniffi wheel (temporary solution until repo is public)
COPY docker/isomdl_uniffi-0.1.0-py3-none-any.whl ./
RUN pip install isomdl_uniffi-0.1.0-py3-none-any.whl --no-cache-dir

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
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=5 \
  CMD curl -f http://localhost:8031/status/ready || exit 1

# Set working directory and run ACA-Py
WORKDIR /usr/src/acapy
CMD ["python", "-m", "acapy_agent", "start", "--arg-file", "/usr/src/app/docker/dev.yml"]
