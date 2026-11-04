package contracts

import (
	"encoding/json"
	"time"
)

type ChallengeRequest struct {
	Sources []string `json:"source_ids"`
	Purpose string   `json:"purpose"`
}
type Challenge struct {
	ID         string    `json:"challenge_id"`
	Tenant     string    `json:"tenant_id"`
	Source     string    `json:"source_id"`
	Generation string    `json:"generation_id"`
	Nonce      string    `json:"nonce"`
	Issued     time.Time `json:"issued_at"`
	Expires    time.Time `json:"expires_at"`
	Purpose    string    `json:"purpose"`
}
type ChallengeResponse struct {
	Challenges []Challenge `json:"challenges"`
}
type Heartbeat struct {
	Version   Version   `json:"schema_version"`
	ID        string    `json:"heartbeat_id"`
	Tenant    string    `json:"tenant_id"`
	Origin    Origin    `json:"origin"`
	Challenge string    `json:"challenge_id"`
	Nonce     string    `json:"nonce"`
	Sequence  string    `json:"heartbeat_sequence"`
	Sent      time.Time `json:"sent_at"`
}
type SignedHeartbeat struct {
	Payload   json.RawMessage `json:"payload"`
	Digest    string          `json:"digest"`
	KeyID     string          `json:"key_id"`
	Signature string          `json:"signature"`
}
type HeartbeatResult struct {
	ID          string    `json:"heartbeat_id"`
	Accepted    time.Time `json:"accepted_at"`
	LastContact time.Time `json:"last_contact_at"`
	Request     string    `json:"request_id"`
}
