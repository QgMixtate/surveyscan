package wire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	jcs "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"net/netip"
	"strconv"
	"strings"
)

type Validator struct{ schemas map[string]*jsonschema.Schema }

func New() (*Validator, error) {
	b, e := contracts.Files.ReadFile("wire.schema.json")
	if e != nil {
		return nil, e
	}
	doc, e := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	id := doc.(map[string]any)["$id"].(string)
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if e = c.AddResource(id, doc); e != nil {
		return nil, e
	}
	v := &Validator{schemas: map[string]*jsonschema.Schema{}}
	extra, e := contracts.Files.ReadFile("c09.schema.json")
	if e != nil {
		return nil, e
	}
	docExtra, e := jsonschema.UnmarshalJSON(bytes.NewReader(extra))
	if e != nil {
		return nil, e
	}
	extraID := docExtra.(map[string]any)["$id"].(string)
	if e = c.AddResource(extraID, docExtra); e != nil {
		return nil, e
	}
	detail, e := c.Compile(extraID + "#/$defs/InventoryDetail")
	if e != nil {
		return nil, e
	}
	v.schemas["InventoryDetail"] = detail

	for _, n := range []string{"ChallengeRequest", "ChallengeResponse", "SignedHeartbeat", "HeartbeatResult", "Observation", "SignedObservation", "BusinessPatch", "Asset", "AssetPage", "OutboxEvent", "EnrollmentGrantRequest", "EnrollmentGrant", "EnrollmentRequest", "EnrollmentResult", "MachineConfig", "RevocationRequest", "Batch", "RecordResult", "SignedCenterResult", "TransportReceipt", "Source", "SourcePage"} {
		s, e := c.Compile(id + "#/$defs/" + n)
		if e != nil {
			return nil, e
		}
		v.schemas[n] = s
	}
	return v, nil
}
func bounded(v any, depth int) bool {
	if depth > 32 {
		return false
	}
	switch x := v.(type) {
	case string:
		return !strings.ContainsRune(x, 0)
	case map[string]any:
		for k, a := range x {
			switch k {
			case "source_sequence", "heartbeat_sequence", "aggregate_version", "lease_version", "revision", "business_revision", "profile_revision", "result_revision":
				str, ok := a.(string)
				if !ok {
					return false
				}
				n, e := strconv.ParseUint(str, 10, 64)
				if e != nil || n == 0 {
					return false
				}
			}
			if strings.ContainsRune(k, 0) || !bounded(a, depth+1) {
				return false
			}
		}
	case []any:
		for _, a := range x {
			if !bounded(a, depth+1) {
				return false
			}
		}
	}
	return true
}
func (v *Validator) Validate(name string, b []byte) error {
	if len(b) == 0 || len(b) > 1048576 {
		return domain.Invalid
	}
	a, e := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if e != nil || !bounded(a, 0) {
		return domain.Invalid
	}
	if _, e = jcs.Transform(b); e != nil {
		return domain.Invalid
	}
	schema, ok := v.schemas[name]
	if !ok {
		return fmt.Errorf("unknown embedded schema")
	}
	if e = schema.Validate(a); e != nil {
		return domain.Invalid
	}
	return nil
}
func Canonical(b []byte) ([]byte, error) { return jcs.Transform(b) }
func (v *Validator) Observation(b []byte) (contracts.SignedObservation, contracts.Observation, []byte, error) {
	var signed contracts.SignedObservation
	var o contracts.Observation
	if e := v.Validate("SignedObservation", b); e != nil {
		return signed, o, nil, e
	}
	_ = json.Unmarshal(b, &signed)
	_ = json.Unmarshal(signed.Payload, &o)
	if o.Version.Major != 1 || o.Version.Minor != 0 {
		return signed, o, nil, domain.Invalid
	}
	if n, e := strconv.ParseUint(o.Sequence, 10, 64); e != nil || n == 0 {
		return signed, o, nil, domain.Invalid
	}
	names := map[string]bool{}
	for _, s := range o.Sections {
		if names[s.Name] || s.Count != len(s.Records) || s.Status == "partial" && s.Complete {
			return signed, o, nil, domain.Invalid
		}
		if s.Status == "unknown" || s.CollectedAt.After(o.CollectedAt) {
			return signed, o, nil, domain.Invalid
		}
		if s.Name == "network" {
			for _, row := range s.Records {
				for _, entry := range row["addresses"].([]any) {
					address := entry.(map[string]any)
					ip, e := netip.ParseAddr(address["ip"].(string))
					prefix, _ := strconv.Atoi(fmt.Sprint(address["prefix"]))
					if e != nil || prefix > ip.BitLen() {
						return signed, o, nil, domain.Invalid
					}
				}
			}
		}
		names[s.Name] = true
	}
	canonical, e := Canonical(signed.Payload)
	if len(canonical) > 65536 {
		return signed, o, nil, domain.Invalid
	}
	return signed, o, canonical, e
}
