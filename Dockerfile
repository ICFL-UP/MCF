FROM node:20-bookworm

# Python 3.11+ and build essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv git make curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv, for Python dependency management 
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"


ENV FOUNDRY_DIR=/usr/local/foundry
ENV PATH="/usr/local/foundry/bin:${PATH}"
RUN set -eux; \
    curl -fL https://getfoundry.sh/install | bash; \
    FU="$(command -v foundryup || true)"; \
    if [ -z "$FU" ]; then \
        FU="$(find /usr/local /root -maxdepth 5 -type f -name foundryup 2>/dev/null | head -1)"; \
    fi; \
    if [ -z "$FU" ]; then echo "foundryup was not installed"; exit 1; fi; \
    "$FU"; \
    BIN="$(dirname "$FU")"; \
    for b in forge cast anvil chisel; do \
        [ -x "$BIN/$b" ] && ln -sf "$BIN/$b" /usr/local/bin/"$b" || true; \
    done; \
    forge --version; \
    cast --version

WORKDIR /work
CMD ["/bin/bash"]
