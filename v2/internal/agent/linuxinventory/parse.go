// Package linuxinventory — чистые парсеры Linux-источников (/proc, /etc, БД пакетов) для секций
// инвентаризации C16.02. Функции принимают содержимое, а не пути: они не читают файловую систему,
// проверяются на фикстурах на любой ОС и не подключены к протоколу (контракт 1.2 пока Windows-only).
// Пароли, хэши, ключи и содержимое пользовательских файлов не разбираются и не возвращаются.
package linuxinventory

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

const maxRows = 10000

type Row = map[string]any

func lines(text string) []string {
	out := []string{}
	s := bufio.NewScanner(strings.NewReader(text))
	s.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for s.Scan() {
		out = append(out, s.Text())
	}
	return out
}

func clean(v string, limit int) string {
	if len(v) > limit || strings.ContainsAny(v, "\x00\r\n") {
		return ""
	}
	return v
}

// Hardware разбирает /proc/cpuinfo и /proc/meminfo в строки kind=cpu и kind=memory.
func Hardware(cpuinfo, meminfo string) []Row {
	rows := []Row{}
	logical, model := 0, ""
	for _, l := range lines(cpuinfo) {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "processor":
			logical++
		case "model name":
			if model == "" {
				model = clean(strings.TrimSpace(v), 256)
			}
		}
	}
	if logical > 0 {
		row := Row{"kind": "cpu", "name": "Logical processors", "logical_processors": logical}
		if model != "" {
			row["model"] = model
		}
		rows = append(rows, row)
	}
	for _, l := range lines(meminfo) {
		if k, v, ok := strings.Cut(l, ":"); ok && k == "MemTotal" {
			f := strings.Fields(v)
			if len(f) == 2 && f[1] == "kB" {
				if n, err := strconv.ParseUint(f[0], 10, 64); err == nil && n > 0 {
					rows = append(rows, Row{"kind": "memory", "name": "Physical memory", "bytes": n * 1024})
				}
			}
		}
	}
	return rows
}

// Packages разбирает /var/lib/dpkg/status: только установленные пакеты.
func Packages(dpkgStatus string) []Row {
	rows := []Row{}
	for _, block := range strings.Split(dpkgStatus, "\n\n") {
		f := map[string]string{}
		for _, l := range lines(block) {
			if l == "" || l[0] == ' ' || l[0] == '\t' {
				continue
			}
			if k, v, ok := strings.Cut(l, ":"); ok {
				f[k] = strings.TrimSpace(v)
			}
		}
		if !strings.HasSuffix(f["Status"], " installed") || strings.HasPrefix(f["Status"], "deinstall") {
			continue
		}
		name := clean(f["Package"], 256)
		if name == "" || len(rows) >= maxRows {
			continue
		}
		row := Row{"name": name, "source": "dpkg", "scope": "machine"}
		if v := clean(f["Version"], 256); v != "" {
			row["version"] = v
		}
		if v := clean(f["Architecture"], 64); v != "" {
			row["architecture"] = v
		}
		rows = append(rows, row)
	}
	return rows
}

// Accounts разбирает /etc/passwd и /etc/group. Поле пароля игнорируется; /etc/shadow не читается.
func Accounts(passwd, group string) []Row {
	rows := []Row{}
	for _, l := range lines(passwd) {
		p := strings.Split(l, ":")
		if len(p) < 7 || strings.HasPrefix(l, "#") {
			continue
		}
		uid, e1 := strconv.ParseUint(p[2], 10, 32)
		gid, e2 := strconv.ParseUint(p[3], 10, 32)
		name := clean(p[0], 256)
		if e1 != nil || e2 != nil || name == "" || len(rows) >= maxRows {
			continue
		}
		row := Row{"kind": "user", "name": name, "uid": uid, "gid": gid}
		if shell := clean(p[6], 256); shell != "" {
			row["shell"] = shell
		}
		rows = append(rows, row)
	}
	for _, l := range lines(group) {
		p := strings.Split(l, ":")
		if len(p) < 4 || strings.HasPrefix(l, "#") {
			continue
		}
		gid, err := strconv.ParseUint(p[2], 10, 32)
		name := clean(p[0], 256)
		if err != nil || name == "" || len(rows) >= maxRows {
			continue
		}
		rows = append(rows, Row{"kind": "group", "name": name, "gid": gid})
		for _, m := range strings.Split(p[3], ",") {
			if m = clean(m, 256); m != "" && len(rows) < maxRows {
				rows = append(rows, Row{"kind": "membership", "name": m, "group": name, "gid": gid})
			}
		}
	}
	return rows
}

var pseudoFS = map[string]bool{"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "cgroup": true, "cgroup2": true,
	"securityfs": true, "debugfs": true, "tracefs": true, "pstore": true, "bpf": true, "autofs": true, "mqueue": true,
	"hugetlbfs": true, "configfs": true, "fusectl": true, "binfmt_misc": true, "overlay": false}

func unescapeMount(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}

// Mounts разбирает /proc/self/mountinfo; служебные ФС отбрасываются.
func Mounts(mountinfo string) []Row {
	rows := []Row{}
	index := map[string]int{}
	for _, l := range lines(mountinfo) {
		before, after, ok := strings.Cut(l, " - ")
		if !ok {
			continue
		}
		b, a := strings.Fields(before), strings.Fields(after)
		if len(b) < 6 || len(a) < 2 || pseudoFS[a[0]] || len(rows) >= maxRows {
			continue
		}
		mp := clean(unescapeMount(b[4]), 4096)
		if mp == "" {
			continue
		}
		row := Row{"kind": "mount", "name": mp, "filesystem": a[0], "device_id": clean(unescapeMount(a[1]), 512), "read_only": strings.Contains(","+b[5]+",", ",ro,")}
		// Несколько монтирований в одну точку (stacked mounts): ключ записи — точка, поэтому
		// остаётся верхнее (последнее в mountinfo); порядок по первому появлению точки.
		if i, dup := index[mp]; dup {
			rows[i] = row
			continue
		}
		index[mp] = len(rows)
		rows = append(rows, row)
	}
	return rows
}

func hexIP(h string, v6 bool) (netip.Addr, bool) {
	raw, err := hex.DecodeString(h)
	if err != nil {
		return netip.Addr{}, false
	}
	if !v6 && len(raw) == 4 { // /proc/net: little-endian слова
		return netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]}), true
	}
	if v6 && len(raw) == 16 {
		var a [16]byte
		for i := 0; i < 16; i += 4 {
			a[i], a[i+1], a[i+2], a[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
		}
		return netip.AddrFrom16(a), true
	}
	return netip.Addr{}, false
}

var tcpStates = map[string]string{"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
	"06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}

// Sockets разбирает /proc/net/{tcp,tcp6,udp,udp6}; PID владельца не определяется (нужен root).
func Sockets(proto, text string, v6 bool) []Row {
	rows := []Row{}
	family := "ipv4"
	if v6 {
		family = "ipv6"
	}
	for i, l := range lines(text) {
		f := strings.Fields(l)
		if i == 0 || len(f) < 4 || len(rows) >= maxRows {
			continue
		}
		la, lp, ok1 := strings.Cut(f[1], ":")
		ra, rp, ok2 := strings.Cut(f[2], ":")
		lip, ok3 := hexIP(la, v6)
		rip, ok4 := hexIP(ra, v6)
		lport, e1 := strconv.ParseUint(lp, 16, 16)
		rport, e2 := strconv.ParseUint(rp, 16, 16)
		if !(ok1 && ok2 && ok3 && ok4) || e1 != nil || e2 != nil {
			continue
		}
		state := tcpStates[strings.ToUpper(f[3])]
		if proto == "udp" {
			state = ""
		} else if state == "" {
			continue
		}
		rowFamily := family
		if v6 && (lip.Is4In6() || rip.Is4In6()) {
			// Двухстековый сокет с IPv4-партнёром (::ffff:a.b.c.d) — это IPv4-соединение; контракт не
			// допускает IPv4-mapped в строках ipv6, поэтому адреса разворачиваются, "::" → 0.0.0.0.
			rowFamily = "ipv4"
			norm := func(a netip.Addr) (netip.Addr, bool) {
				if a.Is4In6() {
					return a.Unmap(), true
				}
				if a.IsUnspecified() {
					return netip.IPv4Unspecified(), true
				}
				return a, a.Is4()
			}
			var ok1, ok2 bool
			lip, ok1 = norm(lip)
			rip, ok2 = norm(rip)
			if !ok1 || !ok2 {
				continue // смешанная пара IPv4/IPv6 не представима в контракте
			}
		}
		row := Row{"kind": proto, "family": rowFamily, "local_address": lip.String(), "local_port": lport, "remote_address": rip.String(), "remote_port": rport}
		if state != "" {
			row["state"] = state
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool { return fmt.Sprint(rows[i]["local_port"]) < fmt.Sprint(rows[j]["local_port"]) })
	return rows
}

// Routes разбирает /proc/net/route (IPv4).
func Routes(text string) []Row {
	rows := []Row{}
	for i, l := range lines(text) {
		f := strings.Fields(l)
		if i == 0 || len(f) < 8 || len(rows) >= maxRows {
			continue
		}
		dst, ok1 := hexIP(f[1], false)
		gw, ok2 := hexIP(f[2], false)
		mask, ok3 := hexIP(f[7], false)
		metric, err := strconv.ParseUint(f[6], 10, 32)
		if !(ok1 && ok2 && ok3) || err != nil {
			continue
		}
		ones := 0
		for _, b := range mask.As4() {
			for ; b != 0; b <<= 1 {
				ones++
			}
		}
		rows = append(rows, Row{"kind": "route", "family": "ipv4", "destination": fmt.Sprintf("%s/%d", dst, ones), "gateway": gw.String(), "interface": clean(f[0], 64), "metric": metric})
	}
	return rows
}
