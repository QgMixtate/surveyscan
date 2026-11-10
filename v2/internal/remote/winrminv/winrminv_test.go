package winrminv

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

const fixture = `{"hostname":"WIN-SRV01","domain":"lab.local","uuid":"4C4C4544-0000-1000-8000-B2C04F000000",
"os":{"caption":"Microsoft Windows Server 2019 Standard","version":"10.0.17763","build":"17763","arch":"64-bit","boot":"2026-11-10T01:38:46Z","memory_kb":4194304},
"bios":{"Vendor":"Phoenix","Version":"6.00","Serial":"To Be Filled By O.E.M."},"cpu_logical":4,"cpu_name":"Intel Xeon",
"nics":[{"index":3,"name":"Intel Ethernet","mac":"00-0C-29-AA-BB-CC","ips":["192.168.1.10","fe80::1","2001:db8::10"],"masks":["255.255.255.0","64","64"],"dns":["192.168.1.1"],"gateways":["192.168.1.1"],"dhcp":false,"mtu":1500}],
"services":[{"name":"WinRM","display":"Windows Remote Management","state":"Running","mode":"Auto","account":"NT AUTHORITY\\NetworkService","path":"C:\\Windows\\System32\\svchost.exe -k NetworkService"},{"name":"Odd","display":"x\u0001y","state":"Weird","mode":"Manual","account":"","path":""}],
"software":[{"view":"64","key":"{ABC}","name":"7-Zip","version":"23.01","vendor":"Igor Pavlov"},{"view":"99","key":"bad","name":"Bad","version":"","vendor":""}]}`

func TestParseNormalizesAndDropsUnsafe(t *testing.T) {
	secs, cands, err := Parse([]byte(fixture), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]contracts.Section{}
	for _, s := range secs {
		by[s.Name] = s
		if s.Complete || s.Status == "ok" {
			t.Fatal("remote profile must be partial:", s.Name)
		}
	}
	if len(cands) != 2 || by["identity"].Records[0]["machine_uuid"] != "4c4c4544-0000-1000-8000-b2c04f000000" {
		t.Fatal(cands, by["identity"].Records)
	}
	os0 := by["os"].Records[0]
	if os0["architecture"] != "amd64" || os0["build"] != "17763" {
		t.Fatal(os0)
	}
	n := by["network"].Records[0]
	addrs := n["addresses"].([]map[string]any)
	if n["mac"] != "00:0c:29:aa:bb:cc" || len(addrs) != 2 || addrs[0]["prefix"] != 24 || addrs[1]["prefix"] != 64 {
		t.Fatalf("link-local must be dropped, prefixes derived: %+v", n)
	}
	hw := by["hardware"].Records
	hasSerial := false
	for _, r := range hw {
		if _, ok := r["serial"]; ok {
			hasSerial = true
		}
	}
	if hasSerial || len(hw) != 3 {
		t.Fatal("placeholder serial must be dropped:", hw)
	}
	if len(by["services"].Records) != 2 || by["services"].Records[1]["state"] != "unknown" || by["services"].Records[1]["display_name"] != nil {
		t.Fatal("control chars / unknown state must not be invented:", by["services"].Records)
	}
	if len(by["software"].Records) != 1 {
		t.Fatal("bad registry view must be dropped:", by["software"].Records)
	}
}

func TestOutputPassesObservationSchema(t *testing.T) {
	b, err := os.ReadFile("../../../../docs/plans/surveyscan-v2/contracts/C15/fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		ID      string                `json:"id"`
		Payload contracts.Observation `json:"payload"`
	}
	if err = json.Unmarshal(b, &fixtures); err != nil {
		t.Fatal(err)
	}
	var o contracts.Observation
	for _, f := range fixtures {
		if f.ID == "all-sections" {
			o = f.Payload
		}
	}
	secs, _, err := Parse([]byte(fixture), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	full := Complete12(secs)
	if len(full) != 12 {
		t.Fatal(len(full))
	}
	o.Sections = full
	o.CollectedAt = time.Now().UTC().Add(time.Minute) // секции не могут быть новее наблюдения
	v, err := wire.NewInventory12()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(o)
	if _, err = v.Payload(raw); err != nil {
		t.Fatal("rejected by observation schema:", err)
	}
}

type fakeRun struct {
	out string
	err error
}

func (f fakeRun) RunPowerShell(ctx context.Context, _ string, _ int) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.out, nil
}

func TestCollectWithFailsClosed(t *testing.T) {
	if _, _, err := CollectWith(context.Background(), fakeRun{err: ErrRun}, Policy{}); !errors.Is(err, ErrRun) {
		t.Fatal(err)
	}
	if _, _, err := CollectWith(context.Background(), fakeRun{out: "not json TOPSECRET"}, Policy{}); err == nil || strings.Contains(err.Error(), "TOPSECRET") {
		t.Fatal("garbage output must fail without echoing it:", err)
	}
	secs, cands, err := CollectWith(context.Background(), fakeRun{out: fixture}, Policy{})
	if err != nil || len(secs) != 12 || len(cands) != 2 {
		t.Fatal(err, len(secs))
	}
}

func TestConnectRequiresHTTPSCAAndSecret(t *testing.T) {
	st := store{}
	for _, tg := range []Target{{}, {Host: "h", User: "u", PasswordAlias: "a"}, {Host: "h", User: "u", CAPEM: []byte("x")}} {
		if _, err := Connect(context.Background(), st, tg, Policy{}); !errors.Is(err, ErrPolicy) {
			t.Errorf("%+v must be rejected: %v", tg, err)
		}
	}
	if _, err := Connect(context.Background(), st, Target{Host: "h", User: "u", PasswordAlias: "a", CAPEM: []byte("x")}, Policy{}); err == nil || strings.Contains(err.Error(), "TOPSECRET") {
		t.Fatal("store error must not leak:", err)
	}
}

type store map[string]string

func (s store) Read(_ context.Context, a string) ([]byte, error) {
	if v, ok := s[a]; ok {
		return []byte(v), nil
	}
	return nil, errors.New("denied TOPSECRET")
}

func TestScriptIsASCII(t *testing.T) {
	for i, r := range Script {
		if r > 127 {
			t.Fatalf("non-ASCII rune %q at %d: the script must not depend on code pages", r, i)
		}
	}
}

func TestScriptFitsWinRMCommandLimit(t *testing.T) {
	if n := EncodedLength(Script); n > 7800 {
		t.Fatalf("encoded script is %d chars; cmd.exe limit is ~8191", n)
	}
	if strings.Contains(Script, "Set-") || strings.Contains(Script, "Remove-") || strings.Contains(Script, "New-Item") || strings.Contains(Script, "Out-File") {
		t.Fatal("script must be read-only")
	}
}

func TestClassifyNeverEchoesTargetText(t *testing.T) {
	cases := map[string]error{
		"http response error: 401 - invalid content type":     ErrAuth,
		"x509: certificate signed by unknown authority":       ErrTLS,
		"dial tcp 10.0.0.1:5986: connect: connection refused": ErrNet,
		"something TOPSECRET else":                            ErrRun,
	}
	for in, want := range cases {
		got := classify(errors.New(in))
		if !errors.Is(got, want) || strings.Contains(got.Error(), "TOPSECRET") {
			t.Errorf("%q -> %v, want %v", in, got, want)
		}
	}
}
