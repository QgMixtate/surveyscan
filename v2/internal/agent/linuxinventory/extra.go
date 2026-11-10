package linuxinventory

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

func sortRows(rows []Row) {
	sort.SliceStable(rows, func(i, j int) bool { return fmt.Sprint(rows[i]["name"]) < fmt.Sprint(rows[j]["name"]) })
}

var archPattern = regexp.MustCompile(`^[A-Za-z0-9_.+-]+$`)

func softwareRow(source, name, version, arch string) Row {
	name = clean(name, 256)
	if name == "" {
		return nil
	}
	row := Row{"name": name, "source": source, "scope": "machine"}
	if v := clean(version, 256); v != "" {
		row["version"] = v
	}
	if archPattern.MatchString(arch) && len(arch) <= 64 {
		row["architecture"] = arch
	}
	return row
}

// RPMPackages разбирает вывод `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'`.
// Пакеты gpg-pubkey (ключи в БД rpm, не программы) пропускаются.
func RPMPackages(text string) []Row {
	rows := []Row{}
	for _, l := range lines(text) {
		f := strings.Split(l, "\t")
		if len(f) < 3 || f[0] == "gpg-pubkey" || len(rows) >= maxRows {
			continue
		}
		if row := softwareRow("rpm", f[0], f[1], f[2]); row != nil {
			rows = append(rows, row)
		}
	}
	return rows
}

// APKPackages разбирает /lib/apk/db/installed (блоки через пустую строку, поля P: V: A:).
func APKPackages(text string) []Row {
	rows := []Row{}
	for _, block := range strings.Split(text, "\n\n") {
		var name, version, arch string
		for _, l := range lines(block) {
			switch {
			case strings.HasPrefix(l, "P:"):
				name = l[2:]
			case strings.HasPrefix(l, "V:"):
				version = l[2:]
			case strings.HasPrefix(l, "A:"):
				arch = l[2:]
			}
		}
		if len(rows) >= maxRows {
			break
		}
		if row := softwareRow("apk", name, version, arch); row != nil {
			rows = append(rows, row)
		}
	}
	return rows
}

func startMode(fileState string) string {
	switch fileState {
	case "enabled", "enabled-runtime", "alias", "generated", "transient":
		return "auto"
	case "static", "indirect":
		return "demand"
	case "disabled", "masked", "masked-runtime":
		return "disabled"
	}
	return "unknown"
}

func serviceState(active, sub string) string {
	switch active {
	case "active", "reloading":
		if sub == "running" || sub == "reload" || active == "reloading" {
			return "running"
		}
		return "stopped" // active (exited): одноразовая служба отработала
	case "activating":
		return "start_pending"
	case "deactivating":
		return "stop_pending"
	case "inactive", "failed":
		return "stopped"
	}
	return "unknown"
}

// SystemdServices объединяет `systemctl list-units --type=service --all --plain --no-legend --no-pager`
// (UNIT LOAD ACTIVE SUB DESCRIPTION...) и `systemctl list-unit-files --type=service --plain --no-legend --no-pager`
// (UNIT STATE ...). Описание unit — display_name; пути, переменные окружения и пользователи не читаются.
func SystemdServices(listUnits, listUnitFiles string) []Row {
	modes := map[string]string{}
	for _, l := range lines(listUnitFiles) {
		if f := strings.Fields(l); len(f) >= 2 && strings.HasSuffix(f[0], ".service") {
			modes[f[0]] = startMode(f[1])
		}
	}
	rows := []Row{}
	seen := map[string]bool{}
	for _, l := range lines(listUnits) {
		l = strings.TrimLeft(l, "●* \t")
		f := strings.Fields(l)
		if len(f) < 4 || !strings.HasSuffix(f[0], ".service") || len(rows) >= maxRows {
			continue
		}
		name := clean(strings.TrimSuffix(f[0], ".service"), 256)
		if name == "" || f[1] == "not-found" {
			continue
		}
		seen[f[0]] = true
		row := Row{"name": name, "state": serviceState(f[2], f[3])}
		if d := clean(strings.Join(f[4:], " "), 256); d != "" {
			row["display_name"] = d
		}
		if m, ok := modes[f[0]]; ok {
			row["start_mode"] = m
		} else {
			row["start_mode"] = "unknown"
		}
		rows = append(rows, row)
	}
	// unit-файлы без загруженного unit (например, disabled и не запускавшиеся) — остановленные
	for unit, mode := range modes {
		name := clean(strings.TrimSuffix(unit, ".service"), 256)
		if seen[unit] || name == "" || strings.HasSuffix(name, "@") || len(rows) >= maxRows {
			continue
		}
		rows = append(rows, Row{"name": name, "state": "stopped", "start_mode": mode})
	}
	sortRows(rows)
	return rows
}

var placeholders = map[string]bool{"": true, "none": true, "default string": true, "to be filled by o.e.m.": true,
	"not specified": true, "system serial number": true, "unknown": true, "0": true}

func dmiValue(v string) string {
	v = strings.TrimSpace(v)
	if placeholders[strings.ToLower(v)] {
		return ""
	}
	return clean(v, 256)
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// DMI собирает строки kind=bios из /sys/class/dmi/id (ключи — имена файлов). product_serial и product_uuid
// доступны только root: при их отсутствии строка выдаётся без serial/uuid. Заглушки производителей отбрасываются.
func DMI(files map[string]string) []Row {
	vendor, version := dmiValue(files["bios_vendor"]), dmiValue(files["bios_version"])
	product, sysVendor := dmiValue(files["product_name"]), dmiValue(files["sys_vendor"])
	if vendor == "" && version == "" && product == "" && sysVendor == "" {
		return []Row{}
	}
	row := Row{"kind": "bios", "name": "System firmware"}
	if version != "" && len(version) <= 200 {
		row["name"] = "BIOS " + version
	}
	if sysVendor != "" {
		row["vendor"] = sysVendor
	} else if vendor != "" {
		row["vendor"] = vendor
	}
	if product != "" {
		row["model"] = product
	}
	if s := dmiValue(files["product_serial"]); s != "" {
		row["serial"] = s
	}
	if u := strings.TrimSpace(files["product_uuid"]); uuidPattern.MatchString(u) && !placeholders[strings.ToLower(u)] {
		row["uuid"] = strings.ToLower(u)
	}
	return []Row{row}
}
