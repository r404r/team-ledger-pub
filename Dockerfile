# syntax=docker/dockerfile:1.7

FROM oven/bun:1.3.14 AS web-build
WORKDIR /src/web
COPY web/package.json web/bun.lock ./
RUN bun install --frozen-lockfile
COPY web/ ./
RUN bun run vite build

FROM golang:1.26.5-bookworm AS go-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/teamledger-api ./cmd/api \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/teamledger-keyd ./cmd/teamledger-keyd \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/teamledger-keyctl-local ./cmd/keyctl-local \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/teamledger-migrate ./cmd/migrate \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/teamledger-backup ./cmd/backup \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/teamledger-key-rewrap ./cmd/key-rewrap \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/teamledger-bonus-hmac ./cmd/bonus-hmac \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/teamledger-identity ./cmd/identity \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/teamledger-staff-reindex ./cmd/staff-reindex \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/teamledger-audit-forwarder ./cmd/audit-forwarder \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/teamledger-audit-receiver ./cmd/audit-receiver \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/teamledger-audit-bootstrap ./cmd/audit-bootstrap \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/teamledger-assessment-worker ./cmd/assessment-worker

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && install -d -o 10001 -g 10001 -m 0700 /var/lib/teamledger
COPY --from=go-build /out/ /app/
COPY --from=web-build /src/web/dist/ /app/web/
ENV TEAMLEDGER_WEB_DIR=/app/web
EXPOSE 8443
USER 10001:10001
CMD ["/app/teamledger-api"]
