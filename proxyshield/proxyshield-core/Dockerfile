FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY . .
RUN go build -o proxyshield-core ./cmd/proxyshield/

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/proxyshield-core .
COPY --from=builder /app/config.json .
COPY --from=builder /app/internal/dashboard/public ./internal/dashboard/public
EXPOSE 9090 9091
CMD ["./proxyshield-core", "--config", "config.json"]
