FROM mcr.microsoft.com/devcontainers/rust:1-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential clang cmake libclang-dev libssl-dev libpq-dev \
        pkg-config postgresql-client python3 python3-pip python3-venv pipx sqlite3 \
    && rm -rf /var/lib/apt/lists/*

USER vscode
    ENV PATH="/home/vscode/.local/bin:${PATH}"
    RUN rustup update stable && rustup component add clippy rustfmt && pipx install poetry