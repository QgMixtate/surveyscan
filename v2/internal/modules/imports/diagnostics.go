package imports

import (
	"context"
)

type Diagnostics struct {
	Pending      int64    `json:"pending_deliveries"`
	PendingBytes int64    `json:"pending_bytes"`
	OldestAge    *float64 `json:"oldest_pending_age_seconds"`
	Retry        int64    `json:"retry_deliveries"`
	DeadLetter   int64    `json:"dead_letter_deliveries"`
}

// Tenant comes only from the authenticated application composition root, never request input.
func (s *UploadService) Diagnostics(ctx context.Context, tenant string) (Diagnostics, error) {
	var out Diagnostics
	e := s.Pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE p.payload IS NOT NULL),COALESCE(sum(octet_length(p.payload)),0),extract(epoch FROM clock_timestamp()-min(d.received_at) FILTER(WHERE p.payload IS NOT NULL))::float8,count(*) FILTER(WHERE c.state='retry'),count(*) FILTER(WHERE c.state='dead_letter') FROM imports.deliveries d JOIN imports.delivery_payloads p USING(tenant_id,delivery_id) LEFT JOIN imports.processing_claims c USING(tenant_id,delivery_id) WHERE d.tenant_id=$1`, tenant).Scan(&out.Pending, &out.PendingBytes, &out.OldestAge, &out.Retry, &out.DeadLetter)
	return out, e
}
