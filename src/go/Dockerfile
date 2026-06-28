FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y \
    build-essential cmake libssl-dev wget golang-go

WORKDIR /app
COPY . .

# Build Go Plugin
WORKDIR /app/src/go/vault-plugin-abe
RUN go build -o build/vault-plugin-abe cmd/vault-plugin-abe/main.go

# --- Final Vault Image ---
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y wget unzip && \
    wget https://releases.hashicorp.com/vault/1.15.6/vault_1.15.6_linux_amd64.zip && \
    unzip vault_1.15.6_linux_amd64.zip && \
    mv vault /usr/local/bin/ && \
    rm vault_1.15.6_linux_amd64.zip

RUN mkdir -p /vault/plugins
COPY --from=builder /app/src/go/vault-plugin-abe/build/vault-plugin-abe /vault/plugins/vault-plugin-abe

RUN chmod +x /vault/plugins/vault-plugin-abe

CMD ["vault", "server", "-dev", "-dev-plugin-dir=/vault/plugins", "-dev-listen-address=0.0.0.0:8200", "-dev-root-token-id=root"]
