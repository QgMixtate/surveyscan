package contracts

import (
	"encoding/json"
	"time"
)

type Renewal struct {
	Version   Version   `json:"schema_version"`
	ID        string    `json:"renewal_id"`
	Tenant    string    `json:"tenant_id"`
	Origin    Origin    `json:"origin"`
	Challenge string    `json:"challenge_id"`
	Nonce     string    `json:"nonce"`
	CSR       string    `json:"csr_pem"`
	Sent      time.Time `json:"sent_at"`
}
type RenewRequest struct {
	Payload   json.RawMessage `json:"payload"`
	Digest    string          `json:"digest"`
	KeyID     string          `json:"key_id"`
	Signature string          `json:"signature"`
}
