# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies for SQLite
RUN apk add --no-cache gcc musl-dev

WORKDIR /app

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with CGO for SQLite support
RUN CGO_ENABLED=1 GOOS=linux go build -o netshield ./cmd/analyzer

# Runtime stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/netshield /usr/local/bin/

# Copy web UI dist
COPY --from=builder /app/web/dist ./web/dist

# Copy jar-analyzer for Java bytecode analysis
COPY --from=builder /app/jar-analyzer ./jar-analyzer

# Create data directory
RUN mkdir -p /data

# Default port
EXPOSE 8080

# Environment variables
ENV NETSHIELD_LICENSE_KEY=""

# Volume for project files
VOLUME ["/project"]

# Default command - serve mode
ENTRYPOINT ["netshield"]
CMD ["--serve", "--port", "8080", "--project", "/project"]
