package collector

import "testing"

func TestCollectorInventory12RequiresManagedIdentityAndExplicitOptIn(t *testing.T) {
	f := credentialSetup(t)
	legacy, err := New(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.client.CloseIdleConnections()
	if legacy.protocol.Supports12() {
		t.Fatal("legacy collector enabled12 by default")
	}
	cfg := f.cfg
	cfg.Inventory12 = true
	cfg.CredentialState = ""
	if _, err = New(cfg); err == nil {
		t.Fatal("unmanaged collector enabled12")
	}
	cfg = f.cfg
	cfg.Inventory12 = true
	optin, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer optin.client.CloseIdleConnections()
	if !optin.protocol.Supports12() {
		t.Fatal("configured collector does not decode12")
	}
}
