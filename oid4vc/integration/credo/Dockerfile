FROM node:18-bookworm AS base
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y python3 build-essential git && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm install

# Copy source code and build
COPY . .
RUN npm install

RUN npm run build


HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 \
  CMD curl -f http://localhost:3020/health || exit 1

EXPOSE 3020

CMD [ "npm", "start" ]
