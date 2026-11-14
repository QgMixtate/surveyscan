package cmdb

import (
	"encoding/json"
	"testing"
)

func TestParseMapLimitsAndRefs(t *testing.T) {
	ok := `{"positions":{"gw:10.0.0.1":{"x":1,"y":2},"subnet:fd00::/64":{"x":0,"y":0}},"devices":[{"id":"m:a","type":"router","label":"R","at":{"x":0,"y":0}}],
"links":[{"id":"m:l","a":"m:a","b":"gw:10.0.0.1","kind":"vpn"}],"groups":[],"notes":[],"overrides":{"host:x":{"hidden":true}}}`
	if _, err := ParseMap([]byte(ok)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{}`,
		`{"positions":{},"devices":[],"links":[],"groups":[],"notes":[],"overrides":{"host:x":{}}}`,
		`{"positions":{"host:x":{"x":2e6,"y":0}},"devices":[],"links":[],"groups":[],"notes":[],"overrides":{}}`,
		`{"positions":{},"devices":[{"id":"m:a","type":"router","label":"","at":{"x":0,"y":0}}],"links":[],"groups":[],"notes":[],"overrides":{}}`,
		`{"positions":{},"devices":[],"links":[{"id":"m:l","a":"host:x","b":"host:x","kind":"copper"}],"groups":[],"notes":[],"overrides":{}}`,
		ok + ` {}`,
	} {
		if _, err := ParseMap([]byte(bad)); err == nil {
			t.Fatal("accepted", bad)
		}
	}
	empty, _ := json.Marshal(EmptyMap())
	if _, err := ParseMap(empty); err != nil {
		t.Fatal("empty map must round-trip", err)
	}
}
