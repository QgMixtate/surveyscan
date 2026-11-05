package architecture

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestImportBoundaries(t *testing.T) {
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "list", "-json", "./...")
	cmd.Dir = "../.."
	data, e := cmd.Output()
	if e != nil {
		t.Fatal(e)
	}
	d := json.NewDecoder(bytes.NewReader(data))
	const base = "github.com/QgMixtate/surveyscan/v2/internal/"
	for {
		var p struct {
			ImportPath string
			Imports    []string
		}
		e = d.Decode(&p)
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		local := strings.TrimPrefix(p.ImportPath, base)
		for _, imp := range p.Imports {
			target := strings.TrimPrefix(imp, base)
			if strings.HasPrefix(local, "platform/") && (strings.HasPrefix(target, "modules/") || strings.HasPrefix(target, "app")) {
				t.Errorf("platform dependency %s -> %s", local, target)
			}
			if strings.HasPrefix(local, "modules/") {
				own := strings.Split(local, "/")[1]
				if target == "app" || strings.HasPrefix(target, "app/") {
					t.Errorf("module depends on composition root")
				}
				if strings.HasPrefix(target, "modules/") {
					parts := strings.Split(target, "/")
					if parts[1] != own && (len(parts) < 3 || parts[2] != "port") {
						t.Errorf("cross-module implementation dependency %s -> %s", local, target)
					}
				}
			}
		}
	}
}
func TestContractsUnchanged(t *testing.T) {
	for dst, src := range map[string]string{"openapi.json": "openapi.json", "wire.schema.json": "schemas/wire.schema.json", "compatibility.json": "compatibility.json", "state-machines.json": "state-machines.json"} {
		a, e := os.ReadFile(filepath.Join("../../contracts", dst))
		if e != nil {
			t.Fatal(e)
		}
		b, e := os.ReadFile(filepath.Join("../../../docs/plans/surveyscan-v2/contracts/C03", src))
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("C03 contract changed: %s", dst)
		}
	}
}
