# The explorer service: the only place that holds the store pass key and plaintext.
# Build it yourself from reviewed source; agents work in the dev container, not here.
FROM rust:1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang libclang-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p askar-explorer

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --user-group --no-create-home explorer \
    && mkdir /shared /proposals && chown explorer:explorer /shared /proposals \
    && chmod 700 /proposals
COPY --from=build /src/target/release/askar-explorer /usr/local/bin/askar-explorer
USER explorer
WORKDIR /config
EXPOSE 7071
ENTRYPOINT ["askar-explorer"]
CMD ["serve", "--agent-listen", "0.0.0.0:7071", "--policy", "/config/policy.toml", "--token-file", "/shared/agent.token"]
