# syntax=docker/dockerfile:1
FROM rust:1.89-bookworm@sha256:948f9b08a66e7fe01b03a98ef1c7568292e07ec2e4fe90d88c07bb14563c84ff AS build
WORKDIR /work
ARG TETHER_BUILD_JOBS=2
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/work/target \
    case "$TETHER_BUILD_JOBS" in 1|2) ;; *) exit 64;; esac \
    && cargo build --locked --release --jobs "$TETHER_BUILD_JOBS" -p tether-ingress --bin tether-server \
    && mkdir -p /out && cp target/release/tether-server /out/tether-server

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /out/tether-server /usr/local/bin/tether-server
COPY THIRD_PARTY_NOTICES.txt /usr/share/doc/tether/THIRD_PARTY_NOTICES.txt
COPY LICENSE /usr/share/doc/tether/LICENSE
USER 65532:65532
EXPOSE 8787 8788
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/tether-server", "--health-check", "127.0.0.1:8787"]
ENTRYPOINT ["/usr/local/bin/tether-server"]
CMD ["--ws-listen", "0.0.0.0:8787", "--tls-listen", "0.0.0.0:8788"]
