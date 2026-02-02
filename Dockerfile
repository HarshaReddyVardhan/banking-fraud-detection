# Build stage
FROM node:20-alpine AS builder

# Install build dependencies (needed for some node modules like tensorflow/onnx)
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install all dependencies
RUN npm install

# Copy source code
COPY tsconfig.json ./
COPY src ./src

# Build TypeScript
RUN npm run build

# Prune dev dependencies
RUN npm prune --production

# Production stage
FROM node:20-alpine AS production

# Support tools
RUN apk add --no-cache dumb-init

WORKDIR /app

# Copy built artifacts and production dependencies
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./

# Use non-root user
USER node

# Environment variables
ENV NODE_ENV=production
ENV PORT=3004

# Expose port
EXPOSE 3004

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3004/api/v1/health', (r) => r.statusCode === 200 ? process.exit(0) : process.exit(1))"


# Use dumb-init for proper signal handling
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Start the application
CMD ["node", "dist/index.js"]
