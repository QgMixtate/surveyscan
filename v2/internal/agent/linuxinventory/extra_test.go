package linuxinventory

import "testing"

func TestRPMAndAPK(t *testing.T) {
	r := RPMPackages("bash\t5.1-2.el9\tx86_64\ngpg-pubkey\t1-2\t(none)\nbad line\nkernel\t5.14-1\t(none)\n")
	if len(r) != 2 || r[0]["source"] != "rpm" || r[0]["version"] != "5.1-2.el9" || r[0]["architecture"] != "x86_64" {
		t.Fatal(r)
	}
	if _, has := r[1]["architecture"]; has { // "(none)" не проходит шаблон схемы
		t.Fatal("(none) architecture must be dropped", r[1])
	}
	a := APKPackages("P:musl\nV:1.2.4-r2\nA:x86_64\nS:123\n\nP:busybox\nV:1.36\nA:x86_64\n")
	if len(a) != 2 || a[0]["name"] != "musl" || a[1]["source"] != "apk" {
		t.Fatal(a)
	}
}

func TestSystemdServices(t *testing.T) {
	units := "  ssh.service loaded active running OpenBSD Secure Shell server\n" +
		"● bad.service loaded failed failed Broken thing\n" +
		"  boot.service loaded active exited One shot\n" +
		"  gone.service not-found inactive dead gone.service\n" +
		"  start.service loaded activating start-pre Starting\n"
	files := "ssh.service enabled enabled\nbad.service disabled enabled\nrare.service static -\nmask.service masked -\ntmpl@.service static -\n"
	rows := SystemdServices(units, files)
	got := map[string]Row{}
	for _, r := range rows {
		got[r["name"].(string)] = r
	}
	if got["ssh"]["state"] != "running" || got["ssh"]["start_mode"] != "auto" || got["ssh"]["display_name"] != "OpenBSD Secure Shell server" {
		t.Fatal(got["ssh"])
	}
	if got["bad"]["state"] != "stopped" || got["bad"]["start_mode"] != "disabled" || got["boot"]["state"] != "stopped" || got["start"]["state"] != "start_pending" {
		t.Fatal(got)
	}
	if got["rare"]["start_mode"] != "demand" || got["mask"]["start_mode"] != "disabled" || got["rare"]["state"] != "stopped" {
		t.Fatal(got)
	}
	if _, ok := got["gone"]; ok {
		t.Fatal("not-found unit must be skipped")
	}
	if _, ok := got["tmpl@"]; ok {
		t.Fatal("template unit must be skipped")
	}
}

func TestDMI(t *testing.T) {
	r := DMI(map[string]string{"bios_vendor": "SeaBIOS", "bios_version": "1.16", "sys_vendor": "QEMU", "product_name": "Standard PC",
		"product_serial": "To Be Filled By O.E.M.", "product_uuid": "4C4C4544-0000-1000-8000-B2C04F000000\n"})
	if len(r) != 1 || r[0]["kind"] != "bios" || r[0]["vendor"] != "QEMU" || r[0]["model"] != "Standard PC" || r[0]["uuid"] != "4c4c4544-0000-1000-8000-b2c04f000000" {
		t.Fatal(r)
	}
	if _, has := r[0]["serial"]; has {
		t.Fatal("placeholder serial must be dropped")
	}
	// без root: serial/uuid недоступны — строка всё равно есть
	if r = DMI(map[string]string{"bios_vendor": "X"}); len(r) != 1 || r[0]["uuid"] != nil {
		t.Fatal(r)
	}
	if len(DMI(map[string]string{})) != 0 || len(DMI(map[string]string{"product_name": "None"})) != 0 {
		t.Fatal("empty DMI must give no rows")
	}
}
