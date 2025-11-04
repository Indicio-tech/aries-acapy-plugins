FROM node:20-slim AS base
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y curl python3 make g++ git && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm ci

# Copy source code and build
COPY . .
RUN npm run build

# Health check endpoint
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:3020/health || exit 1

EXPOSE 3020

CMD ["npm", "start"]
