# The stand-in identity provider and the application the end-to-end tests
# protect. It is built from the repository root, like the gated image, so that
# both share one module cache.
#
# This is test scaffolding and is never published.

FROM golang:1.27 AS build
WORKDIR /src

COPY go.mod go.sum ./
COPY hack/ hack/

ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -o /out/testsrv ./hack/e2e/testsrv

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/testsrv /testsrv
USER 65532:65532
ENTRYPOINT ["/testsrv"]
