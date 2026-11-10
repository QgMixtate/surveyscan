package snmpnet

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

type deviceWalker struct {
	g       *gosnmp.GoSNMP
	rows    int
	minGap  time.Duration
	last    time.Time
	maxRows int
}

func (d *deviceWalker) pace(ctx context.Context) error {
	if wait := d.minGap - time.Since(d.last); wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	d.last = time.Now()
	return ctx.Err()
}

// Walk — GETBULK по поддереву с ограничением частоты, строк и отменой контекста. Ответы noSuchObject/endOfMib → пусто.
func (d *deviceWalker) Walk(ctx context.Context, oid string) ([]gosnmp.SnmpPDU, error) {
	out := []gosnmp.SnmpPDU{}
	cur := oid
	for len(out) < d.maxRows {
		if err := d.pace(ctx); err != nil {
			return out, err
		}
		pkt, err := d.g.GetBulk([]string{cur}, 0, d.g.MaxRepetitions)
		if err != nil {
			return out, errors.New("snmp: request failed")
		}
		if pkt.Error != gosnmp.NoError {
			return out, errors.New("snmp: device refused the request")
		}
		progressed := false
		for _, p := range pkt.Variables {
			if p.Type == gosnmp.EndOfMibView || p.Type == gosnmp.NoSuchObject || p.Type == gosnmp.NoSuchInstance || !strings.HasPrefix(p.Name, oid+".") {
				return out, nil
			}
			out = append(out, p)
			cur = p.Name
			progressed = true
			if len(out) >= d.maxRows {
				return out, nil
			}
		}
		if !progressed {
			return out, nil
		}
	}
	return out, nil
}

// Collect открывает SNMPv3-сессию authPriv (ключи читаются непосредственно перед сессией) и собирает таблицы.
func Collect(ctx context.Context, r SecretReader, addr string, p Profile) (Result, error) {
	p, err := p.withDefaults()
	if err != nil {
		return Result{}, err
	}
	host, portStr, err := net.SplitHostPort(addr)
	port, perr := strconv.Atoi(portStr)
	if err != nil || perr != nil || port < 1 || port > 65535 {
		return Result{}, errors.New("snmp: address must be host:port")
	}
	authKey, e1 := r.Read(ctx, p.AuthAlias)
	privKey, e2 := r.Read(ctx, p.PrivAlias)
	defer func() {
		for _, b := range [][]byte{authKey, privKey} {
			for i := range b {
				b[i] = 0
			}
		}
	}()
	if e1 != nil || e2 != nil {
		return Result{}, errors.New("snmp: credential store unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, p.Deadline)
	defer cancel()
	g := &gosnmp.GoSNMP{
		Target: host, Port: uint16(port), Version: gosnmp.Version3, Timeout: p.Timeout, Retries: p.Retries,
		MaxRepetitions: p.MaxReps, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv, Context: ctx,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName: p.User, AuthenticationProtocol: authProtos[strings.ToUpper(p.AuthProto)], AuthenticationPassphrase: string(authKey),
			PrivacyProtocol: privProtos[strings.ToUpper(p.PrivProto)], PrivacyPassphrase: string(privKey),
		},
	}
	if err = g.Connect(); err != nil {
		return Result{}, errors.New("snmp: connect failed")
	}
	defer g.Conn.Close()
	// Проверка учётных данных до сбора: отказ аутентификации не должен превращаться в «все таблицы пусты».
	if _, err = g.Get([]string{oidSystem + ".5.0"}); err != nil {
		return Result{}, ErrAuth
	}
	w := &deviceWalker{g: g, minGap: p.MinInterval, maxRows: p.MaxRows}
	return Gather(ctx, w, p.MaxRows), ctx.Err()
}
