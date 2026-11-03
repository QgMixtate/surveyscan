package migrate

import (
	"testing"
	"testing/fstest"
)

func TestCatalogValidation(t *testing.T) {
	for _, ms := range [][]Migration{nil, {{ID: "x", Owner: "a", SQL: " "}}, {{ID: "x", Owner: "a", SQL: "SELECT 1"}, {ID: "x", Owner: "b", SQL: "SELECT 2"}}} {
		if _, err := ordered(ms); err == nil {
			t.Fatal("invalid catalog accepted")
		}
	}
	a, err := ordered([]Migration{{"b", "a", "SELECT 2"}, {"a", "a", "SELECT 1"}})
	if err != nil || a[0].ID != "a" {
		t.Fatal(a, err)
	}
}
func TestEmbeddedChecksum(t *testing.T) {
	ms, e := FromFS("owner", fstest.MapFS{"schema/0001.sql": &fstest.MapFile{Data: []byte("SELECT 1")}})
	if e != nil || len(ms) != 1 || ms[0].ID != "0001" {
		t.Fatal(ms, e)
	}
	changed := ms[0]
	changed.SQL += ";"
	if checksum(ms[0]) == checksum(changed) {
		t.Fatal("checksum does not detect edit")
	}
}
