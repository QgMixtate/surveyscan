// Package snmpnet — безагентный сбор инвентаря сетевых устройств по SNMPv3 (C19.02/C19.03).
// Только SNMPv3 authPriv (v1/v2c и community запрещены профилем), только GET/GETBULK (запись невозможна),
// ключи — из хранилища секретов по алиасу, лимиты частоты/времени/строк, статус на каждую таблицу.
package snmpnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

var (
	ErrProfile = errors.New("snmp: only SNMPv3 authPriv profiles are allowed")
	ErrAuth    = errors.New("snmp: authentication failed or device unreachable")
)

// SecretReader — как у SSH: алиас из конфигурации оператора, не путь хранилища.
type SecretReader interface {
	Read(ctx context.Context, alias string) ([]byte, error)
}

// Profile — профиль доступа. Секреты берутся по алиасам; в Profile их значений нет.
type Profile struct {
	User        string
	AuthProto   string // SHA | SHA256 | SHA512
	PrivProto   string // AES | AES256
	AuthAlias   string
	PrivAlias   string
	Timeout     time.Duration // один запрос
	Retries     int           // повторы запроса (0..3)
	MaxReps     uint32        // GETBULK max-repetitions
	MinInterval time.Duration // пауза между запросами (ограничение частоты)
	MaxRows     int           // строк на таблицу
	Deadline    time.Duration // весь сбор
}

func (p Profile) withDefaults() (Profile, error) {
	if p.User == "" || p.AuthAlias == "" || p.PrivAlias == "" {
		return p, ErrProfile
	}
	if _, ok := authProtos[strings.ToUpper(p.AuthProto)]; !ok {
		return p, ErrProfile
	}
	if _, ok := privProtos[strings.ToUpper(p.PrivProto)]; !ok {
		return p, ErrProfile
	}
	if p.Timeout <= 0 {
		p.Timeout = 3 * time.Second
	}
	if p.Retries < 0 || p.Retries > 3 {
		p.Retries = 1
	}
	if p.MaxReps == 0 || p.MaxReps > 50 {
		p.MaxReps = 10
	}
	if p.MaxRows <= 0 || p.MaxRows > 100000 {
		p.MaxRows = 20000
	}
	if p.Deadline <= 0 {
		p.Deadline = 3 * time.Minute
	}
	return p, nil
}

var authProtos = map[string]gosnmp.SnmpV3AuthProtocol{"SHA": gosnmp.SHA, "SHA256": gosnmp.SHA256, "SHA512": gosnmp.SHA512}
var privProtos = map[string]gosnmp.SnmpV3PrivProtocol{"AES": gosnmp.AES, "AES256": gosnmp.AES256}

// Walker выполняет обход поддерева. Реализация для устройства — deviceWalker; в тестах — таблица фикстур.
type Walker interface {
	Walk(ctx context.Context, oid string) ([]gosnmp.SnmpPDU, error)
}

// Status таблицы: ok (есть строки), empty (отвечено, строк нет — функция не используется на устройстве),
// unavailable (нет прав/нет объекта/таймаут), truncated (достигнут лимит строк).
type Status string

const (
	StatusOK          Status = "ok"
	StatusEmpty       Status = "empty"
	StatusUnavailable Status = "unavailable"
	StatusTruncated   Status = "truncated"
)

type System struct {
	Name, Descr, ObjectID, Location string
	UptimeTicks                     uint32
}
type Interface struct {
	Index                   int
	Name, Descr, Alias, MAC string
	Type, MTU               int
	SpeedMbps               uint64
	AdminUp, OperUp         bool
	Addresses               []netip.Prefix
}
type ARPEntry struct {
	IfIndex int
	IP      netip.Addr
	MAC     string
}
type FDBEntry struct {
	MAC     string
	IfIndex int // 0, если порт не сопоставлен
	Port    int
	Status  int
	VLAN    int // 0 для dot1d (без VLAN)
}
type Neighbor struct {
	LocalPort                   int
	ChassisID, PortID, PortDesc string
	ChassisSubtype, PortSubtype int
	SysName, SysDesc            string
}
type VLAN struct {
	ID   int
	Name string
}
type Result struct {
	System     System
	Interfaces []Interface
	ARP        []ARPEntry
	FDB        []FDBEntry
	Neighbors  []Neighbor
	VLANs      []VLAN
	Tables     map[string]Status
}

const (
	oidSystem   = ".1.3.6.1.2.1.1"
	oidIfTable  = ".1.3.6.1.2.1.2.2.1"
	oidIfX      = ".1.3.6.1.2.1.31.1.1.1"
	oidIPAddr   = ".1.3.6.1.2.1.4.20.1"
	oidARP      = ".1.3.6.1.2.1.4.22.1"
	oidFDB      = ".1.3.6.1.2.1.17.4.3.1"
	oidBasePort = ".1.3.6.1.2.1.17.1.4.1.2"
	oidLLDPRem  = ".1.0.8802.1.1.2.1.4.1.1"
	oidVLANName = ".1.3.6.1.2.1.17.7.1.4.3.1.1"
)

// suffix возвращает индекс (хвост OID) строки после префикса таблицы+столбца или "" если OID не из этого столбца.
func suffix(name, prefix string) (string, bool) {
	if !strings.HasPrefix(name, prefix+".") {
		return "", false
	}
	return name[len(prefix)+1:], true
}

func pduString(p gosnmp.SnmpPDU) string {
	switch v := p.Value.(type) {
	case []byte:
		if len(v) > 512 || strings.ContainsAny(string(v), "\x00\r\n") {
			return ""
		}
		return string(v)
	case string:
		return v
	}
	return ""
}

func pduMAC(p gosnmp.SnmpPDU) string {
	b, ok := p.Value.([]byte)
	if !ok || len(b) != 6 {
		return ""
	}
	if b[0]|b[1]|b[2]|b[3]|b[4]|b[5] == 0 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func pduInt(p gosnmp.SnmpPDU) (int64, bool) {
	switch v := p.Value.(type) {
	case int:
		return int64(v), true
	case uint:
		return int64(v), true
	case int64:
		return v, true
	case uint32:
		return int64(v), true
	case uint64:
		return int64(v), true
	}
	return 0, false
}

func pduOID(p gosnmp.SnmpPDU) string {
	if s, ok := p.Value.(string); ok {
		return s
	}
	return ""
}

func parseSystem(pdus []gosnmp.SnmpPDU) System {
	var s System
	for _, p := range pdus {
		switch p.Name {
		case oidSystem + ".1.0":
			s.Descr = pduString(p)
		case oidSystem + ".2.0":
			s.ObjectID = pduOID(p)
		case oidSystem + ".3.0":
			if v, ok := pduInt(p); ok {
				s.UptimeTicks = uint32(v)
			}
		case oidSystem + ".5.0":
			s.Name = pduString(p)
		case oidSystem + ".6.0":
			s.Location = pduString(p)
		}
	}
	return s
}

func parseInterfaces(ifTable, ifX, ipAddr []gosnmp.SnmpPDU) []Interface {
	byIdx := map[int]*Interface{}
	get := func(i int) *Interface {
		if x, ok := byIdx[i]; ok {
			return x
		}
		x := &Interface{Index: i}
		byIdx[i] = x
		return x
	}
	for _, p := range ifTable {
		for col, apply := range map[string]func(*Interface, gosnmp.SnmpPDU){
			".2": func(x *Interface, p gosnmp.SnmpPDU) { x.Descr = pduString(p) },
			".3": func(x *Interface, p gosnmp.SnmpPDU) { v, _ := pduInt(p); x.Type = int(v) },
			".4": func(x *Interface, p gosnmp.SnmpPDU) { v, _ := pduInt(p); x.MTU = int(v) },
			".5": func(x *Interface, p gosnmp.SnmpPDU) {
				if v, ok := pduInt(p); ok && x.SpeedMbps == 0 {
					x.SpeedMbps = uint64(v) / 1000000
				}
			},
			".6": func(x *Interface, p gosnmp.SnmpPDU) { x.MAC = pduMAC(p) },
			".7": func(x *Interface, p gosnmp.SnmpPDU) { v, _ := pduInt(p); x.AdminUp = v == 1 },
			".8": func(x *Interface, p gosnmp.SnmpPDU) { v, _ := pduInt(p); x.OperUp = v == 1 },
		} {
			if s, ok := suffix(p.Name, oidIfTable+col); ok {
				if i, err := strconv.Atoi(s); err == nil && i > 0 {
					apply(get(i), p)
				}
			}
		}
	}
	for _, p := range ifX {
		if s, ok := suffix(p.Name, oidIfX+".1"); ok {
			if i, err := strconv.Atoi(s); err == nil && i > 0 {
				get(i).Name = pduString(p)
			}
		}
		if s, ok := suffix(p.Name, oidIfX+".15"); ok { // ifHighSpeed, Мбит/с
			if i, err := strconv.Atoi(s); err == nil && i > 0 {
				if v, ok := pduInt(p); ok && v > 0 {
					get(i).SpeedMbps = uint64(v)
				}
			}
		}
		if s, ok := suffix(p.Name, oidIfX+".18"); ok {
			if i, err := strconv.Atoi(s); err == nil && i > 0 {
				get(i).Alias = pduString(p)
			}
		}
	}
	// ipAddrTable: .1 адрес (индекс = сам адрес), .2 ifIndex, .3 маска
	idxOf, maskOf := map[string]int{}, map[string]string{}
	for _, p := range ipAddr {
		if s, ok := suffix(p.Name, oidIPAddr+".2"); ok {
			if v, ok := pduInt(p); ok {
				idxOf[s] = int(v)
			}
		}
		if s, ok := suffix(p.Name, oidIPAddr+".3"); ok {
			if m, ok := p.Value.(string); ok {
				maskOf[s] = m
			}
		}
	}
	for addr, i := range idxOf {
		a, err := netip.ParseAddr(addr)
		m, err2 := netip.ParseAddr(maskOf[addr])
		if err != nil || err2 != nil || !a.Is4() || !m.Is4() {
			continue
		}
		bits := 0
		for _, b := range m.As4() {
			for ; b != 0; b <<= 1 {
				bits += int(b >> 7)
			}
		}
		if x, ok := byIdx[i]; ok {
			x.Addresses = append(x.Addresses, netip.PrefixFrom(a, bits))
		}
	}
	out := make([]Interface, 0, len(byIdx))
	for _, x := range byIdx {
		sort.Slice(x.Addresses, func(i, j int) bool { return x.Addresses[i].String() < x.Addresses[j].String() })
		out = append(out, *x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

func parseARP(pdus []gosnmp.SnmpPDU) []ARPEntry {
	type row struct {
		mac string
		ok  bool
	}
	macs := map[string]row{}
	for _, p := range pdus {
		if s, ok := suffix(p.Name, oidARP+".2"); ok { // индекс: ifIndex.a.b.c.d
			macs[s] = row{pduMAC(p), true}
		}
	}
	out := []ARPEntry{}
	for key, r := range macs {
		dot := strings.IndexByte(key, '.')
		if dot < 0 || r.mac == "" {
			continue
		}
		i, err := strconv.Atoi(key[:dot])
		a, err2 := netip.ParseAddr(key[dot+1:])
		if err != nil || err2 != nil || !a.Is4() {
			continue
		}
		out = append(out, ARPEntry{IfIndex: i, IP: a, MAC: r.mac})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IfIndex != out[j].IfIndex {
			return out[i].IfIndex < out[j].IfIndex
		}
		return out[i].IP.Less(out[j].IP)
	})
	return out
}

func macFromIndex(parts []string) (string, bool) {
	if len(parts) != 6 {
		return "", false
	}
	b := make([]byte, 6)
	for i, s := range parts {
		v, err := strconv.Atoi(s)
		if err != nil || v < 0 || v > 255 {
			return "", false
		}
		b[i] = byte(v)
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]), true
}

func parseFDB(fdb, basePort []gosnmp.SnmpPDU) []FDBEntry {
	portIf := map[int]int{}
	for _, p := range basePort {
		if s, ok := suffix(p.Name, oidBasePort); ok {
			port, err := strconv.Atoi(s)
			if v, ok2 := pduInt(p); err == nil && ok2 {
				portIf[port] = int(v)
			}
		}
	}
	byMAC := map[string]*FDBEntry{}
	for _, p := range fdb {
		for col, set := range map[string]func(*FDBEntry, int){
			".2": func(e *FDBEntry, v int) { e.Port = v; e.IfIndex = portIf[v] },
			".3": func(e *FDBEntry, v int) { e.Status = v },
		} {
			if s, ok := suffix(p.Name, oidFDB+col); ok {
				mac, ok2 := macFromIndex(strings.Split(s, "."))
				v, ok3 := pduInt(p)
				if !ok2 || !ok3 {
					continue
				}
				e := byMAC[mac]
				if e == nil {
					e = &FDBEntry{MAC: mac}
					byMAC[mac] = e
				}
				set(e, int(v))
			}
		}
	}
	out := []FDBEntry{}
	for _, e := range byMAC {
		if e.Port > 0 {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

func lldpID(subtype int, p gosnmp.SnmpPDU) string {
	b, ok := p.Value.([]byte)
	if !ok {
		return pduString(p)
	}
	if (subtype == 4 || subtype == 3) && len(b) == 6 { // macAddress (chassis=4, port=3)
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
	}
	return pduString(p)
}

func parseLLDP(pdus []gosnmp.SnmpPDU) []Neighbor {
	type key struct{ port, idx string }
	rows := map[key]*Neighbor{}
	sub := map[key][2]int{}
	raw := map[key][2]gosnmp.SnmpPDU{}
	for _, p := range pdus {
		for _, col := range []string{".4", ".5", ".6", ".7", ".8", ".9", ".10"} {
			s, ok := suffix(p.Name, oidLLDPRem+col)
			if !ok {
				continue
			}
			parts := strings.Split(s, ".") // timeMark.localPort.remIndex
			if len(parts) != 3 {
				continue
			}
			k := key{parts[1], parts[2]}
			n := rows[k]
			if n == nil {
				lp, _ := strconv.Atoi(parts[1])
				n = &Neighbor{LocalPort: lp}
				rows[k] = n
			}
			v, _ := pduInt(p)
			ss := sub[k]
			rr := raw[k]
			switch col {
			case ".4":
				ss[0] = int(v)
			case ".5":
				rr[0] = p
			case ".6":
				ss[1] = int(v)
			case ".7":
				rr[1] = p
			case ".8":
				n.PortDesc = pduString(p)
			case ".9":
				n.SysName = pduString(p)
			case ".10":
				n.SysDesc = pduString(p)
			}
			sub[k], raw[k] = ss, rr
		}
	}
	out := []Neighbor{}
	for k, n := range rows {
		n.ChassisSubtype, n.PortSubtype = sub[k][0], sub[k][1]
		n.ChassisID = lldpID(n.ChassisSubtype, raw[k][0])
		n.PortID = lldpID(n.PortSubtype, raw[k][1])
		if n.ChassisID != "" {
			out = append(out, *n)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LocalPort != out[j].LocalPort {
			return out[i].LocalPort < out[j].LocalPort
		}
		return out[i].ChassisID < out[j].ChassisID
	})
	return out
}

func parseVLANs(pdus []gosnmp.SnmpPDU) []VLAN {
	out := []VLAN{}
	for _, p := range pdus {
		if s, ok := suffix(p.Name, oidVLANName); ok {
			if id, err := strconv.Atoi(s); err == nil && id >= 1 && id <= 4094 {
				out = append(out, VLAN{ID: id, Name: pduString(p)})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Gather собирает все таблицы через Walker. Сбой одной таблицы не отбрасывает остальные.
func Gather(ctx context.Context, w Walker, maxRows int) Result {
	r := Result{Tables: map[string]Status{}}
	walk := func(name, oid string) []gosnmp.SnmpPDU {
		pdus, err := w.Walk(ctx, oid)
		switch {
		case err != nil:
			r.Tables[name] = StatusUnavailable
			return nil
		case len(pdus) == 0:
			r.Tables[name] = StatusEmpty
		case len(pdus) >= maxRows:
			r.Tables[name] = StatusTruncated
		default:
			r.Tables[name] = StatusOK
		}
		return pdus
	}
	r.System = parseSystem(walk("system", oidSystem))
	ifT, ifX, ipA := walk("if_table", oidIfTable), walk("if_x_table", oidIfX), walk("ip_addr", oidIPAddr)
	r.Interfaces = parseInterfaces(ifT, ifX, ipA)
	r.ARP = parseARP(walk("arp", oidARP))
	r.FDB = parseFDB(walk("fdb", oidFDB), walk("bridge_ports", oidBasePort))
	r.Neighbors = parseLLDP(walk("lldp", oidLLDPRem))
	r.VLANs = parseVLANs(walk("vlan", oidVLANName))
	return r
}
