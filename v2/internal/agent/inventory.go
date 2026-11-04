// Package agent содержит read-only сбор и исходящий клиент минимального host agent.
package agent

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

type Snapshot struct {
	Candidates []contracts.Candidate `json:"identity_candidates"`
	Sections   []contracts.Section   `json:"sections"`
}

// readSmall не исполняет shell/внешние команды и не читает неограниченные файлы.
func readSmall(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("inventory input unavailable")
	}
	return b, nil
}
func parseOSRelease(raw string) (string, string, error) {
	values := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key != "NAME" && key != "VERSION_ID" && key != "ID" {
			continue
		}
		// os-release — данные, а не shell. Никакой интерполяции или eval.
		if strings.HasPrefix(value, "\"") {
			unquoted, e := strconv.Unquote(value)
			if e != nil {
				return "", "", e
			}
			value = unquoted
		} else if strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") {
			value = strings.Trim(value, "'")
		}
		values[key] = value
	}
	name, version := values["NAME"], values["VERSION_ID"]
	if name == "" {
		name = values["ID"]
	}
	if scanner.Err() != nil || name == "" || version == "" || len(name) > 128 || len(version) > 128 || strings.ContainsAny(name+version, "\x00\r\n") {
		return "", "", errors.New("OS identification unavailable")
	}
	return name, version, nil
}
func section(name string, at time.Time, rows []map[string]any, complete bool, reason string) contracts.Section {
	status := "ok"
	if !complete {
		status = "partial"
		if len(rows) == 0 {
			status = "unavailable"
		}
	}
	return contracts.Section{Name: name, CollectedAt: at, Status: status, Complete: complete, Reason: reason, Count: len(rows), Records: rows}
}

// Collect читает только identity, os-release и локальные интерфейсы. Сетевые цели не опрашиваются.
func Collect(ctx context.Context) (Snapshot, error) {
	if runtime.GOOS != "linux" {
		return Snapshot{}, errors.New("host inventory currently supports Linux only")
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	out := Snapshot{Candidates: []contracts.Candidate{}, Sections: []contracts.Section{}}
	at := time.Now().UTC()
	identity := []map[string]any{}
	host, e := os.Hostname()
	complete := e == nil && host != "" && len(host) <= 255
	if complete {
		row := map[string]any{"hostname": host}
		out.Candidates = append(out.Candidates, contracts.Candidate{Kind: "hostname", Namespace: "dns", Value: host})
		// Linux machine-id является признаком, а не asset_uid и не разрешением cross-source merge.
		if raw, e := readSmall("/etc/machine-id", 128); e == nil {
			id := strings.TrimSpace(string(raw))
			if len(id) == 32 {
				id = id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:]
			}
			if identifier.Valid(id) {
				row["machine_uuid"] = id
				out.Candidates = append(out.Candidates, contracts.Candidate{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: id})
			}
		}
		identity = append(identity, row)
	}
	reason := "COLLECTED"
	if !complete {
		reason = "HOSTNAME_UNAVAILABLE"
	}
	out.Sections = append(out.Sections, section("identity", at, identity, complete, reason))
	osRows := []map[string]any{}
	raw, err := readSmall("/etc/os-release", 65536)
	if err != nil {
		raw, err = readSmall("/usr/lib/os-release", 65536)
	}
	if err == nil {
		name, version, e := parseOSRelease(string(raw))
		err = e
		if err == nil {
			osRows = append(osRows, map[string]any{"name": name, "version": version, "architecture": runtime.GOARCH})
		}
	}
	reason = "COLLECTED"
	if err != nil {
		reason = "OS_RELEASE_UNAVAILABLE"
	}
	out.Sections = append(out.Sections, section("os", time.Now().UTC(), osRows, err == nil, reason))
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	network := []map[string]any{}
	interfaces, err := net.Interfaces()
	complete = err == nil
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Index < interfaces[j].Index })
	for _, nic := range interfaces {
		if len(network) >= 512 {
			complete = false
			break
		}
		if nic.Flags&net.FlagLoopback != 0 {
			continue
		}
		if nic.Name == "" || len(nic.Name) > 128 {
			complete = false
			continue
		}
		addresses := []map[string]any{}
		ips, e := nic.Addrs()
		if e != nil {
			complete = false
		}
		for _, a := range ips {
			ip, prefix, e := net.ParseCIDR(a.String())
			if e != nil {
				complete = false
				continue
			}
			ones, _ := prefix.Mask.Size()
			if len(addresses) == 64 {
				complete = false
				break
			}
			addresses = append(addresses, map[string]any{"ip": ip.String(), "prefix": ones})
		}
		row := map[string]any{"name": nic.Name, "addresses": addresses}
		if len(nic.HardwareAddr) == 6 {
			row["mac"] = strings.ToLower(nic.HardwareAddr.String())
		}
		network = append(network, row)
	}
	reason = "COLLECTED"
	if !complete {
		reason = "NETWORK_COLLECTION_INCOMPLETE"
	}
	out.Sections = append(out.Sections, section("network", time.Now().UTC(), network, complete, reason))
	return out, ctx.Err()
}
