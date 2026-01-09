# Build stage
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -extldflags '-static'" \
    -o securetrace \
    ./cmd/securetrace

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -g '' securetrace
USER securetrace

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/securetrace /app/securetrace

ENTRYPOINT ["/app/securetrace"]
CMD ["--help"]
