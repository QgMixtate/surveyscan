package cmdb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/jackc/pgx/v5"
)

// C22.04: редактируемая схема сети (контракт contracts/c22-network-map.schema.json). Документ хранит только ручной
// слой — раскладку, добавленные устройства, связи, группы, подписи и переопределения; наблюдаемая схема строится
// заново из фактов, а ручной слой накладывается поверх неё. Узлы ручного слоя имеют идентификаторы вида "m:…".

type MapPoint struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

type MapDevice struct {
	ID    string   `json:"id"`
	Type  string   `json:"type"`
	Label string   `json:"label"`
	Note  string   `json:"note,omitempty"`
	Addr  string   `json:"address,omitempty"`
	At    MapPoint `json:"at"`
}

type MapLink struct {
	ID    string `json:"id"`
	A     string `json:"a"`
	B     string `json:"b"`
	Kind  string `json:"kind"`
	PortA string `json:"port_a,omitempty"`
	PortB string `json:"port_b,omitempty"`
	Label string `json:"label,omitempty"`
}

type MapGroup struct {
	ID     string   `json:"id"`
	Label  string   `json:"label"`
	Color  string   `json:"color"`
	At     MapPoint `json:"at"`
	Width  float64  `json:"width"`
	Height float64  `json:"height"`
}

type MapNote struct {
	ID   string   `json:"id"`
	Text string   `json:"text"`
	At   MapPoint `json:"at"`
}

type MapOverride struct {
	Type   string `json:"type,omitempty"`
	Label  string `json:"label,omitempty"`
	Hidden bool   `json:"hidden,omitempty"`
}

type MapDocument struct {
	Positions map[string]MapPoint    `json:"positions"`
	Devices   []MapDevice            `json:"devices"`
	Links     []MapLink              `json:"links"`
	Groups    []MapGroup             `json:"groups"`
	Notes     []MapNote              `json:"notes"`
	Overrides map[string]MapOverride `json:"overrides"`
}

type NetworkMap struct {
	Revision  string      `json:"revision"`
	UpdatedAt *time.Time  `json:"updated_at"`
	UpdatedBy *string     `json:"updated_by"`
	Document  MapDocument `json:"document"`
}

var (
	DeviceTypes = map[string]bool{"server": true, "workstation": true, "virtual_machine": true, "hypervisor": true, "switch": true, "router": true,
		"firewall": true, "access_point": true, "printer": true, "storage": true, "cloud": true, "other": true}
	linkKinds   = map[string]bool{"copper": true, "fiber": true, "wireless": true, "trunk": true, "vpn": true, "virtual": true, "logical": true}
	groupColors = map[string]bool{"green": true, "blue": true, "amber": true, "red": true, "gray": true, "violet": true}
	nodeRef     = regexp.MustCompile(`^(host|subnet|gw|m):[A-Za-z0-9:._/%-]{1,160}$`)
	manualRef   = regexp.MustCompile(`^m:[A-Za-z0-9_-]{1,64}$`)
)

const (
	mapMaxPositions = 20000
	mapMaxDevices   = 2000
	mapMaxLinks     = 5000
	mapMaxGroups    = 500
	mapMaxNotes     = 1000
	mapMaxBytes     = 1 << 20
	mapCoordLimit   = 1e6
)

func EmptyMap() MapDocument {
	return MapDocument{Positions: map[string]MapPoint{}, Devices: []MapDevice{}, Links: []MapLink{}, Groups: []MapGroup{}, Notes: []MapNote{}, Overrides: map[string]MapOverride{}}
}

func text(s string, min, max int) bool {
	n := utf8.RuneCountInString(s)
	return utf8.ValidString(s) && n >= min && n <= max && !bytes.ContainsAny([]byte(s), "\x00")
}

func point(p MapPoint) bool {
	return !math.IsNaN(p.X) && !math.IsNaN(p.Y) && math.Abs(p.X) <= mapCoordLimit && math.Abs(p.Y) <= mapCoordLimit
}

// ParseMap — строгий разбор и проверка документа: неизвестные поля, лимиты, ссылки связей на существующие в
// документе ручные устройства или на наблюдаемые узлы (их наличие проверяется при показе — узел мог исчезнуть).
func ParseMap(raw []byte) (MapDocument, error) {
	var doc MapDocument // все шесть разделов обязательны: пустой раздел — [] или {}
	if len(raw) > mapMaxBytes {
		return doc, domain.Invalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&doc) != nil || d.More() {
		return doc, domain.Invalid
	}
	if doc.Positions == nil || doc.Devices == nil || doc.Links == nil || doc.Groups == nil || doc.Notes == nil || doc.Overrides == nil ||
		len(doc.Positions) > mapMaxPositions || len(doc.Devices) > mapMaxDevices || len(doc.Links) > mapMaxLinks || len(doc.Groups) > mapMaxGroups ||
		len(doc.Notes) > mapMaxNotes || len(doc.Overrides) > mapMaxPositions {
		return doc, domain.Invalid
	}
	for id, p := range doc.Positions {
		if !nodeRef.MatchString(id) || !point(p) {
			return doc, domain.Invalid
		}
	}
	ids := map[string]bool{}
	unique := func(id string) bool {
		if !manualRef.MatchString(id) || ids[id] {
			return false
		}
		ids[id] = true
		return true
	}
	devices := map[string]bool{}
	for _, v := range doc.Devices {
		if !unique(v.ID) || !DeviceTypes[v.Type] || !text(v.Label, 1, 120) || !text(v.Note, 0, 1000) || !text(v.Addr, 0, 120) || !point(v.At) {
			return doc, domain.Invalid
		}
		devices[v.ID] = true
	}
	for _, l := range doc.Links {
		if !unique(l.ID) || !linkKinds[l.Kind] || !nodeRef.MatchString(l.A) || !nodeRef.MatchString(l.B) || l.A == l.B ||
			!text(l.PortA, 0, 64) || !text(l.PortB, 0, 64) || !text(l.Label, 0, 120) {
			return doc, domain.Invalid
		}
		for _, end := range []string{l.A, l.B} {
			if end[:2] == "m:" && !devices[end] {
				return doc, domain.Invalid
			}
		}
	}
	for _, g := range doc.Groups {
		if !unique(g.ID) || !text(g.Label, 1, 120) || !groupColors[g.Color] || !point(g.At) || g.Width < 80 || g.Height < 60 || g.Width > 20000 || g.Height > 20000 {
			return doc, domain.Invalid
		}
	}
	for _, n := range doc.Notes {
		if !unique(n.ID) || !text(n.Text, 1, 1000) || !point(n.At) {
			return doc, domain.Invalid
		}
	}
	for id, o := range doc.Overrides {
		if !nodeRef.MatchString(id) || o.Type != "" && !DeviceTypes[o.Type] || !text(o.Label, 0, 120) || o.Type == "" && o.Label == "" && !o.Hidden {
			return doc, domain.Invalid
		}
	}
	return doc, nil
}

func (Store) NetworkMap(ctx context.Context, tx pgx.Tx, tenant string) (NetworkMap, error) {
	out := NetworkMap{Revision: "0", Document: EmptyMap()}
	var raw []byte
	var by string
	var at time.Time
	e := tx.QueryRow(ctx, "SELECT document,revision::text,updated_at,updated_by::text FROM cmdb.network_maps WHERE tenant_id=$1 AND map_name='main'", tenant).Scan(&raw, &out.Revision, &at, &by)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, nil
	}
	if e != nil {
		return out, e
	}
	if out.Document, e = ParseMap(raw); e != nil {
		return out, e
	}
	out.UpdatedAt, out.UpdatedBy = &at, &by
	return out, nil
}

// SaveNetworkMap заменяет документ при совпадении ревизии ("0" — документа ещё нет); иначе domain.Revision.
func (s Store) SaveNetworkMap(ctx context.Context, tx pgx.Tx, tenant, actor, revision string, doc MapDocument) (NetworkMap, error) {
	raw, e := json.Marshal(doc)
	if e != nil {
		return NetworkMap{}, e
	}
	if _, e = ParseMap(raw); e != nil {
		return NetworkMap{}, e
	}
	var affected int64
	if revision == "0" {
		tag, err := tx.Exec(ctx, "INSERT INTO cmdb.network_maps(tenant_id,document,updated_by) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", tenant, raw, actor)
		e, affected = err, tag.RowsAffected()
	} else {
		tag, err := tx.Exec(ctx, "UPDATE cmdb.network_maps SET document=$3,revision=revision+1,updated_at=now(),updated_by=$4 WHERE tenant_id=$1 AND map_name='main' AND revision::text=$2", tenant, revision, raw, actor)
		e, affected = err, tag.RowsAffected()
	}
	if e != nil {
		return NetworkMap{}, e
	}
	if affected != 1 {
		return NetworkMap{}, domain.Revision
	}
	return s.NetworkMap(ctx, tx, tenant)
}
