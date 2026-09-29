# Prahari API and CLI: static, CGO-free, distroless, non-root.
#   docker build -t prahari-api backend/
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG COMMIT=dev
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags "-s -w -X main.commit=${COMMIT}" -o /out/api ./cmd/api \
 && go build -trimpath -ldflags "-s -w" -o /out/cli ./cmd/cli \
 && mkdir -p /out/data/truth

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/api /out/cli /app/
COPY --from=build /src/data/attack /app/data/attack
# Ground truth written at simulation time; owned by the non-root user so a
# named volume mounted here inherits writable permissions.
COPY --from=build --chown=nonroot:nonroot /out/data/truth /app/data/truth
# -trimpath removes the compiled-in source path, so tell config.Root() where
# the bundle and data directory live.
ENV PRAHARI_HOME=/app \
    PRAHARI_HTTP_ADDR=:8000
USER nonroot:nonroot
EXPOSE 8000
ENTRYPOINT ["/app/api"]
