# Runtime only. Build the plugin on Linux with make vault before testing.
ARG VAULT_RUNTIME_BASE=ubuntu:24.04
FROM ${VAULT_RUNTIME_BASE}
ARG VAULT_VERSION=2.0.4
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip libstdc++6 && \
    cd /tmp && \
    curl -fsSLO "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_${TARGETARCH}.zip" && \
    curl -fsSLO "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_SHA256SUMS" && \
    grep " vault_${VAULT_VERSION}_linux_${TARGETARCH}.zip$" "vault_${VAULT_VERSION}_SHA256SUMS" | sha256sum -c - && \
    unzip "vault_${VAULT_VERSION}_linux_${TARGETARCH}.zip" vault -d /usr/local/bin && \
    rm -f /tmp/vault_* && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /vault/plugins /vault/config && \
    printf 'plugin_directory = "/vault/plugins"\n' > /vault/config/server.hcl
CMD ["vault", "server", "-dev", "-config=/vault/config/server.hcl", "-dev-listen-address=0.0.0.0:8200", "-dev-root-token-id=root"]
