package migrate

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestCatalogExactCompiledBytesAndOrder(t *testing.T) {
	ms := []Migration{{ID: "0002", Owner: "second", SQL: "SELECT 2;\n"}, {ID: "0001", Owner: "first", SQL: "SELECT 1;\n"}}
	rows, err := Catalog(ms)
	if err != nil || len(rows) != 2 || rows[0].ID != "0001" || rows[1].Owner != "second" {
		t.Fatal("invalid compiled catalog", err)
	}
	if rows[0].SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(ms[1].SQL))) {
		t.Fatal("schema catalog must use the exact migration checksum")
	}
	ms[0].ID = "0001"
	if _, err := Catalog(ms); err == nil {
		t.Fatal("ambiguous catalog accepted")
	}
}
