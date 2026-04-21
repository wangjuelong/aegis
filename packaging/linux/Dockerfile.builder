FROM rust:1.94-bookworm

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      bpftool \
      build-essential \
      ca-certificates \
      clang \
      dpkg-dev \
      libdbus-1-dev \
      libssl-dev \
      llvm \
      pkg-config \
      rpm && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
