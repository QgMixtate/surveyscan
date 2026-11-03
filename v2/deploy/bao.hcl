# Local C04 development only: loopback-published HTTP, Raft storage, one local unseal share.
# Production TLS, policies, machine issuance and split custody are C05/C11/C13 scope.
disable_mlock = true
ui = false
api_addr = "http://bao:8200"
cluster_addr = "https://bao:8201"
storage "raft" {
  path = "/openbao/file"
  node_id = "surveyscan-v2-c04"
}
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true
}
