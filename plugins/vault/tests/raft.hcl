# Isolated test service only. Uses Vault's default request/entry size limits.
disable_mlock = true
api_addr = "http://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"
storage "raft" {
  path = "/tmp/hcpabe-raft-test"
  node_id = "isolated-test"
}
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true
}
