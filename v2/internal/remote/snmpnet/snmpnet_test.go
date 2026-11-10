package snmpnet

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func oc(name string, v any) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: name, Value: v, Type: gosnmp.OctetString}
}
func in(name string, v int) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: name, Value: v, Type: gosnmp.Integer}
}

type fakeWalker map[string][]gosnmp.SnmpPDU

func (f fakeWalker) Walk(_ context.Context, oid string) ([]gosnmp.SnmpPDU, error) {
	if v, ok := f[oid]; ok {
		return v, nil
	}
	if oid == oidVLANName {
		return nil, errors.New("snmp: device refused the request") // нет прав на таблицу
	}
	return nil, nil
}

func TestGatherNormalizesAndKeepsTablesIndependent(t *testing.T) {
	mac := []byte{0x52, 0x54, 0, 0x12, 0x34, 0x56}
	w := fakeWalker{
		oidSystem: {oc(oidSystem+".5.0", []byte("sw1")), oc(oidSystem+".1.0", []byte("Test switch"))},
		oidIfTable: {oc(oidIfTable+".2.1", []byte("Gi0/1")), in(oidIfTable+".3.1", 6), in(oidIfTable+".4.1", 1500),
			oc(oidIfTable+".6.1", mac), in(oidIfTable+".7.1", 1), in(oidIfTable+".8.1", 1)},
		oidIfX:      {oc(oidIfX+".1.1", []byte("Gi0/1")), {Name: oidIfX + ".15.1", Value: uint(1000), Type: gosnmp.Gauge32}, oc(oidIfX+".18.1", []byte("uplink"))},
		oidIPAddr:   {in(oidIPAddr+".2.10.0.0.1", 1), {Name: oidIPAddr + ".3.10.0.0.1", Value: "255.255.255.0", Type: gosnmp.IPAddress}},
		oidARP:      {oc(oidARP+".2.1.10.0.0.9", []byte{0xaa, 0xbb, 0xcc, 0, 0, 1})},
		oidFDB:      {in(oidFDB+".2.170.187.204.0.0.1", 3), in(oidFDB+".3.170.187.204.0.0.1", 3)},
		oidBasePort: {in(oidBasePort+".3", 1)},
		oidLLDPRem: {in(oidLLDPRem+".4.0.1.1", 4), oc(oidLLDPRem+".5.0.1.1", []byte{0, 1, 2, 3, 4, 5}), in(oidLLDPRem+".6.0.1.1", 5),
			oc(oidLLDPRem+".7.0.1.1", []byte("Gi0/24")), oc(oidLLDPRem+".9.0.1.1", []byte("core1"))},
	}
	r := Gather(context.Background(), w, 1000)
	if r.System.Name != "sw1" || len(r.Interfaces) != 1 {
		t.Fatal(r.System, r.Interfaces)
	}
	i := r.Interfaces[0]
	if i.Name != "Gi0/1" || i.MAC != "52:54:00:12:34:56" || i.SpeedMbps != 1000 || !i.OperUp || i.Alias != "uplink" || len(i.Addresses) != 1 || i.Addresses[0].String() != "10.0.0.1/24" {
		t.Fatalf("%+v", i)
	}
	if len(r.ARP) != 1 || r.ARP[0].IP.String() != "10.0.0.9" || r.ARP[0].MAC != "aa:bb:cc:00:00:01" {
		t.Fatal(r.ARP)
	}
	if len(r.FDB) != 1 || r.FDB[0].MAC != "aa:bb:cc:00:00:01" || r.FDB[0].IfIndex != 1 {
		t.Fatal(r.FDB)
	}
	if len(r.Neighbors) != 1 || r.Neighbors[0].ChassisID != "00:01:02:03:04:05" || r.Neighbors[0].PortID != "Gi0/24" || r.Neighbors[0].SysName != "core1" {
		t.Fatalf("%+v", r.Neighbors)
	}
	// права на VLAN-таблицу отсутствуют: она unavailable, остальные таблицы не затронуты
	if r.Tables["vlan"] != StatusUnavailable || r.Tables["system"] != StatusOK || r.Tables["bridge_ports"] != StatusOK {
		t.Fatal(r.Tables)
	}
}

func TestTruncationIsReported(t *testing.T) {
	w := fakeWalker{oidARP: {oc(oidARP+".2.1.10.0.0.1", []byte{1, 2, 3, 4, 5, 6}), oc(oidARP+".2.1.10.0.0.2", []byte{1, 2, 3, 4, 5, 7})}}
	if r := Gather(context.Background(), w, 2); r.Tables["arp"] != StatusTruncated {
		t.Fatal(r.Tables["arp"])
	}
}

type store map[string]string

func (s store) Read(_ context.Context, a string) ([]byte, error) {
	v, ok := s[a]
	if !ok {
		return nil, errors.New("denied TOPSECRET")
	}
	return []byte(v), nil
}

func TestProfileRejectsWeakModes(t *testing.T) {
	for _, p := range []Profile{{}, {User: "u", AuthAlias: "a", PrivAlias: "p", AuthProto: "MD5", PrivProto: "AES"},
		{User: "u", AuthAlias: "a", PrivAlias: "p", AuthProto: "SHA", PrivProto: "DES"}, {User: "u", AuthAlias: "a", AuthProto: "SHA", PrivProto: "AES"}} {
		if _, err := Collect(context.Background(), store{}, "127.0.0.1:161", p); !errors.Is(err, ErrProfile) {
			t.Errorf("%+v must be rejected: %v", p, err)
		}
	}
	_, err := Collect(context.Background(), store{}, "127.0.0.1:161", Profile{User: "u", AuthAlias: "a", PrivAlias: "p", AuthProto: "SHA", PrivProto: "AES"})
	if err == nil || strings.Contains(err.Error(), "TOPSECRET") {
		t.Fatal("store error must not leak:", err)
	}
}

// Живая проверка против настоящего snmpd (net-snmp); включается переменными окружения.
func TestLiveSNMPv3(t *testing.T) {
	addr := os.Getenv("SURVEYSCAN_TEST_SNMP_ADDR")
	if addr == "" {
		t.Skip("SURVEYSCAN_TEST_SNMP_ADDR не задан")
	}
	p := Profile{User: "probe", AuthProto: "SHA", PrivProto: "AES", AuthAlias: "a", PrivAlias: "p", Timeout: 2 * time.Second, MinInterval: 5 * time.Millisecond}
	good := store{"a": os.Getenv("SURVEYSCAN_TEST_SNMP_AUTH"), "p": os.Getenv("SURVEYSCAN_TEST_SNMP_PRIV")}
	r, err := Collect(context.Background(), good, addr, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("system=%q interfaces=%d arp=%d tables=%v", r.System.Name, len(r.Interfaces), len(r.ARP), r.Tables)
	if r.System.Name == "" || len(r.Interfaces) == 0 || r.Tables["if_table"] != StatusOK {
		t.Fatal("live data missing", r.Tables)
	}
	// неверный ключ: отказ аутентификации, а не «пустые таблицы»
	bad := store{"a": "wrong-auth-pass", "p": os.Getenv("SURVEYSCAN_TEST_SNMP_PRIV")}
	if _, err = Collect(context.Background(), bad, addr, p); !errors.Is(err, ErrAuth) {
		t.Fatal("wrong key must give ErrAuth:", err)
	}
}
