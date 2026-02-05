# Multi-stage build — adjust base image to match your app runtime
# This example assumes a Node.js/Python FastAPI app; adapt as needed.

# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build 2>/dev/null || true

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM node:20-alpine AS runtime
WORKDIR /app

# Download AWS RDS CA bundle for DocumentDB TLS connections
RUN apk add --no-cache wget && \
    wget -q https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem \
      -O /tmp/rds-combined-ca-bundle.pem && \
    apk del wget

COPY --from=builder /app .

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

CMD ["node", "dist/index.js"]
