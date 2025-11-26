FROM node:20-slim AS base
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y curl python3 make g++ git && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm ci --legacy-peer-deps || npm install --legacy-peer-deps

# Rebuild native dependencies explicitly if needed, but npm usually handles it.
# We force a rebuild of the problematic packages just in case.
RUN npm rebuild @2060.io/ref-napi @2060.io/ffi-napi --build-from-source

# Copy source code and build
COPY . .
RUN npm run build


HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:3020/health || exit 1

EXPOSE 3020

CMD [ "npm", "start" ]
