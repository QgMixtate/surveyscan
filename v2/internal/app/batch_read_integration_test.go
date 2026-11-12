//go:build integration

package app_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
)

// C30 (стенд): пакетное чтение страницы реестра даёт те же карточки, что и чтение каждого актива отдельно.
func TestBatchListMatchesSingleReads(t *testing.T) {
	f := registrySetup(t)
	for i := range 7 {
		o := f.observation("1")
		mu := fmt.Sprintf("00000000-0000-4000-8000-%012d", 900+i)
		o.Record.LocalID = fmt.Sprintf("batch-%d", i)
		o.Candidates = []contracts.Candidate{{Kind: "machine_uuid", Namespace: "host", Value: mu}}
		o.Sections[0].Records = []map[string]any{{"hostname": fmt.Sprintf("batch-%d", i), "machine_uuid": mu}}
		if r := f.ingest(t, o); r.AssetID == nil {
			t.Fatal("asset not created", r)
		}
	}
	page, err := f.registry.List(f.ctx, f.identity, "", 200)
	if err != nil || len(page.Items) < 7 {
		t.Fatal(len(page.Items), err)
	}
	for _, listed := range page.Items {
		single, err := f.registry.Get(f.ctx, f.identity, listed.UID)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := json.Marshal(listed)
		b, _ := json.Marshal(single)
		if string(a) != string(b) {
			t.Fatalf("batch and single reads differ:\n%s\n%s", a, b)
		}
	}
}
