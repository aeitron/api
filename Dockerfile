# Multi-stage production build for Aeitron API Gateway
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod ./
COPY *.go ./
COPY openapi.yaml ./
COPY cmd/ ./cmd/

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /app/bin/api-gateway ./cmd/api-gateway

FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata && \
    addgroup -S aeitron && adduser -S aeitron -G aeitron

WORKDIR /home/aeitron
COPY --from=builder /app/bin/api-gateway /usr/local/bin/api-gateway

USER aeitron:aeitron
EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/api-gateway"]
