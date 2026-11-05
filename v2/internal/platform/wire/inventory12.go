package wire

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

// Inventory12MaxPayload is a draft payload bound, not a negotiated transport limit.
// Existing SignedObservation/collector/registry handlers still accept only C03.
const Inventory12MaxPayload = 1 << 20

// Inventory12Validator validates an unsigned payload for future C15 integration.
// It neither verifies signatures nor authorizes/adopts an origin or asset UID.
type Inventory12Validator struct{ schema *jsonschema.Schema }

func NewInventory12() (*Inventory12Validator, error) {
	b, err := contracts.C15Files.ReadFile("c15.schema.json")
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	id := "urn:surveyscan:c15:observation:1:2"
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err = c.AddResource(id, doc); err != nil {
		return nil, err
	}
	schema, err := c.Compile(id)
	if err != nil {
		return nil, err
	}
	return &Inventory12Validator{schema: schema}, nil
}

// Payload returns JCS bytes only after schema and cross-field checks pass. Its
// caller must perform the existing binding/signature/admission checks separately.
func (v *Inventory12Validator) Payload(b []byte) ([]byte, error) {
	if len(b) == 0 || len(b) > Inventory12MaxPayload {
		return nil, domain.Invalid
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil || !bounded(doc, 0) || v.schema.Validate(doc) != nil {
		return nil, domain.Invalid
	}
	canonical, err := Canonical(b)
	if err != nil || len(canonical) > Inventory12MaxPayload {
		return nil, domain.Invalid
	}
	var payload struct {
		CollectedAt time.Time           `json:"collected_at"`
		Sections    []contracts.Section `json:"sections"`
	}
	if json.Unmarshal(b, &payload) != nil {
		return nil, domain.Invalid
	}
	names := make(map[string]bool, 12)
	for _, section := range payload.Sections {
		if names[section.Name] || section.Count != len(section.Records) || section.CollectedAt.After(payload.CollectedAt) {
			return nil, domain.Invalid
		}
		names[section.Name] = true
		for _, row := range section.Records {
			if !inventory12Addresses(section.Name, row) {
				return nil, domain.Invalid
			}
		}
	}
	return canonical, nil
}

func inventory12Addresses(section string, row map[string]any) bool {
	check := func(raw any, family string) bool {
		s, ok := raw.(string)
		if !ok {
			return false
		}
		ip, err := netip.ParseAddr(s)
		return err == nil && (family == "" || family == "ipv4" && ip.Is4() || family == "ipv6" && ip.Is6() && !ip.Is4In6())
	}
	switch section {
	case "network":
		for _, entry := range row["addresses"].([]any) {
			address := entry.(map[string]any)
			ip, err := netip.ParseAddr(address["ip"].(string))
			if err != nil || int(address["prefix"].(float64)) > ip.BitLen() {
				return false
			}
		}
		for _, key := range []string{"dns_servers", "gateways"} {
			if values, ok := row[key].([]any); ok {
				for _, value := range values {
					if !check(value, "") {
						return false
					}
				}
			}
		}
	case "neighbors", "routes_ports":
		family := row["family"].(string)
		for _, key := range []string{"address", "local_address", "remote_address", "gateway"} {
			if value, ok := row[key]; ok && !check(value, family) {
				return false
			}
		}
		if value, ok := row["destination"]; ok {
			prefix, err := netip.ParsePrefix(value.(string))
			if err != nil || !check(prefix.Addr().String(), family) {
				return false
			}
		}
	}
	return true
}
