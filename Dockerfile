# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
	-trimpath \
	-ldflags "-s -w -X github.com/ongoingai/gateway/internal/version.Version=${VERSION} -X github.com/ongoingai/gateway/internal/version.Commit=${COMMIT} -X github.com/ongoingai/gateway/internal/version.Date=${DATE}" \
	-o /out/ongoingai ./cmd/ongoingai && \
	mkdir -p /out/data

FROM scratch

WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/ongoingai /ongoingai
COPY --from=builder --chown=65532:65532 /out/data /app/data
COPY --chown=65532:65532 ongoingai.example.yaml /app/ongoingai.yaml

USER 65532:65532

EXPOSE 8080

ENTRYPOINT ["/ongoingai"]
CMD ["serve", "--config", "/app/ongoingai.yaml"]
