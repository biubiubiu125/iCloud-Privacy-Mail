FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG APP_VERSION=dev
ARG APP_COMMIT=unknown
ARG APP_BUILT_AT=

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X icloud-privacy-mail/internal/app.AppVersion=${APP_VERSION} -X icloud-privacy-mail/internal/app.AppCommit=${APP_COMMIT} -X icloud-privacy-mail/internal/app.AppBuiltAt=${APP_BUILT_AT}" \
    -o /out/icloud-privacy-mail ./cmd/panel

FROM alpine:3.22

RUN apk add --no-cache ca-certificates su-exec \
    && addgroup -S ipm && adduser -S ipm -G ipm \
    && mkdir -p /app/data

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
WORKDIR /app
COPY --from=builder /out/icloud-privacy-mail /app/icloud-privacy-mail
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && chown -R ipm:ipm /app

USER root

EXPOSE 8787
VOLUME ["/app/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -q -T 5 -O /dev/null http://127.0.0.1:8787/api/v1/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--host", "0.0.0.0", "--config", "/app/data/config.json"]
