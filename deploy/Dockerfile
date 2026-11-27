# Build from the repository root: docker build -f deploy/Dockerfile -t kumokeep .

FROM node:24-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS server
WORKDIR /src/server
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
COPY --from=web /src/web/build/ ./internal/web/dist/
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /kumokeep ./cmd/kumokeep

# Distroless: no shell, no package manager, runs as non-root.
# Note: once photo thumbnails use libvips (cgo), this becomes a distroless/cc image with libvips copied in.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=server /kumokeep /kumokeep
ENV KUMOKEEP_ADDR=0.0.0.0:8080 \
    KUMOKEEP_DATA_DIR=/data \
    KUMOKEEP_TRUST_PROXY=true
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/kumokeep"]
CMD ["serve"]
