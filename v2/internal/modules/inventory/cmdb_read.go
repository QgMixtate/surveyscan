package inventory

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// C26.02 — чтение нормализованных сведений CMDB из проекции 1.2 (представления миграции 0039) с provenance.

type Evidence struct {
	ObservationID string    `json:"observation_id"`
	SourceID      string    `json:"source_id"`
	SourceKind    string    `json:"source_kind"`
	CollectedAt   time.Time `json:"collected_at"`
	ClockQuality  string    `json:"clock_quality"`
}

type Installation struct {
	RecordKey    string   `json:"record_key"`
	Name         *string  `json:"name"`
	Version      *string  `json:"version"`
	Publisher    *string  `json:"publisher"`
	Architecture *string  `json:"architecture"`
	Source       *string  `json:"package_source"`
	Evidence     Evidence `json:"evidence"`
}

type Component struct {
	Section   string   `json:"section"`
	RecordKey string   `json:"record_key"`
	Kind      *string  `json:"kind"`
	Name      *string  `json:"name"`
	Vendor    *string  `json:"vendor"`
	Model     *string  `json:"model"`
	Serial    *string  `json:"serial"`
	SizeBytes *string  `json:"size_bytes"`
	Evidence  Evidence `json:"evidence"`
}

// Software — установки ПО актива: стабильная сортировка по имени без учёта регистра, затем ключ записи;
// курсор — ключ последней записи (keyset по паре имя+ключ).
func (Store) Software(ctx context.Context, tx pgx.Tx, tenant, asset, filter, after string, limit int) ([]Installation, error) {
	rows, e := tx.Query(ctx, `SELECT i.record_key,i.name,i.version,i.publisher,i.architecture,i.package_source,
o.observation_id::text,o.source_id::text,o.payload->'origin'->>'source_kind',s.collected_at,o.clock_quality
FROM inventory.software_installations12 i
JOIN inventory.observations o ON o.tenant_id=i.tenant_id AND o.observation_id=i.observation_id
JOIN inventory.observation_sections s ON s.tenant_id=i.tenant_id AND s.observation_id=i.observation_id AND s.section_name='software'
WHERE i.tenant_id=$1 AND i.asset_uid=$2 AND ($3='' OR lower(i.name) LIKE '%'||lower($3)||'%' OR lower(i.publisher) LIKE '%'||lower($3)||'%')
AND ($4='' OR (lower(COALESCE(i.name,'')),i.record_key)>(SELECT lower(COALESCE(c.name,'')),c.record_key FROM inventory.software_installations12 c WHERE c.tenant_id=$1 AND c.asset_uid=$2 AND c.record_key=$4))
ORDER BY lower(COALESCE(i.name,'')),i.record_key LIMIT $5`, tenant, asset, filter, after, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Installation{}
	for rows.Next() {
		var i Installation
		if e = rows.Scan(&i.RecordKey, &i.Name, &i.Version, &i.Publisher, &i.Architecture, &i.Source, &i.Evidence.ObservationID, &i.Evidence.SourceID, &i.Evidence.SourceKind, &i.Evidence.CollectedAt, &i.Evidence.ClockQuality); e != nil {
			return nil, e
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (Store) Components(ctx context.Context, tx pgx.Tx, tenant, asset string) ([]Component, error) {
	rows, e := tx.Query(ctx, `SELECT c.section_name,c.record_key,c.kind,c.name,c.vendor,c.model,c.serial,c.size_bytes,
o.observation_id::text,o.source_id::text,o.payload->'origin'->>'source_kind',s.collected_at,o.clock_quality
FROM inventory.components12 c
JOIN inventory.observations o ON o.tenant_id=c.tenant_id AND o.observation_id=c.observation_id
JOIN inventory.observation_sections s ON s.tenant_id=c.tenant_id AND s.observation_id=c.observation_id AND s.section_name=c.section_name
WHERE c.tenant_id=$1 AND c.asset_uid=$2 ORDER BY c.section_name,c.kind,c.name,c.record_key LIMIT 2000`, tenant, asset)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Component{}
	for rows.Next() {
		var c Component
		if e = rows.Scan(&c.Section, &c.RecordKey, &c.Kind, &c.Name, &c.Vendor, &c.Model, &c.Serial, &c.SizeBytes, &c.Evidence.ObservationID, &c.Evidence.SourceID, &c.Evidence.SourceKind, &c.Evidence.CollectedAt, &c.Evidence.ClockQuality); e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

type Product struct {
	Name      string   `json:"name"`
	Publisher *string  `json:"publisher"`
	Installs  int      `json:"installations"`
	Assets    int      `json:"assets"`
	Versions  []string `json:"versions"`
	AssetUIDs []string `json:"asset_uids"`
}

// Products — поиск ПО по подстроке имени во всём тенанте (AM-10): продукт = нормализованное имя + издатель.
func (Store) Products(ctx context.Context, tx pgx.Tx, tenant, query string, limit int) ([]Product, error) {
	rows, e := tx.Query(ctx, `SELECT min(name),publisher,count(*)::int,count(DISTINCT asset_uid)::int,
(array_agg(DISTINCT version) FILTER (WHERE version IS NOT NULL))[1:20],
(array_agg(DISTINCT asset_uid::text))[1:50]
FROM inventory.software_installations12 WHERE tenant_id=$1 AND name IS NOT NULL AND lower(name) LIKE '%'||lower($2)||'%'
GROUP BY lower(name),publisher ORDER BY lower(name),publisher NULLS FIRST LIMIT $3`, tenant, query, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Product{}
	for rows.Next() {
		var p Product
		if e = rows.Scan(&p.Name, &p.Publisher, &p.Installs, &p.Assets, &p.Versions, &p.AssetUIDs); e != nil {
			return nil, e
		}
		if p.Versions == nil {
			p.Versions = []string{}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Counts — число установок ПО и компонентов актива.
func (Store) Counts(ctx context.Context, tx pgx.Tx, tenant, asset string) (int, int, error) {
	var software, components int
	e := tx.QueryRow(ctx, `SELECT (SELECT count(DISTINCT record_key) FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='software'),
(SELECT count(DISTINCT (section_name,record_key)) FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name IN ('hardware','resources'))`, tenant, asset).Scan(&software, &components)
	return software, components, e
}

// ObservedClass — класс актива по фактам (C26.01): виртуальная машина по модели оборудования, сервер/рабочая
// станция по ОС. Возвращает класс и причину; без фактов — unknown.
func (Store) ObservedClass(ctx context.Context, tx pgx.Tx, tenant, asset string) (string, string, error) {
	var model, vendor, osName *string
	e := tx.QueryRow(ctx, `SELECT
(SELECT string_agg(value #>> '{}',' ') FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='hardware' AND field_name='model'),
(SELECT string_agg(value #>> '{}',' ') FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='hardware' AND field_name='vendor'),
COALESCE((SELECT max(value #>> '{}') FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='os' AND field_name='name'),
 (SELECT max(value) FROM inventory.current_facts WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='os' AND fact_key='name'))`, tenant, asset).Scan(&model, &vendor, &osName)
	if e != nil {
		return "", "", e
	}
	class, reason := classify(deref(model)+" "+deref(vendor), deref(osName))
	return class, reason, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func classify(hardware, osName string) (string, string) {
	h, o := strings.ToLower(hardware), strings.ToLower(osName)
	for _, marker := range []string{"virtual machine", "vmware", "kvm", "qemu", "virtualbox", "innotek", "hvm domu", "xen", "bochs", "parallels", "standard pc ("} {
		if strings.Contains(h, marker) {
			return "virtual_machine", "HARDWARE_MODEL_VIRTUAL"
		}
	}
	switch {
	case o == "":
		return "unknown", "NO_FACTS"
	case strings.Contains(o, "windows") && strings.Contains(o, "server"):
		return "server", "OS_SERVER_EDITION"
	case strings.Contains(o, "windows"):
		return "workstation", "OS_CLIENT_EDITION"
	case strings.Contains(o, "linux") || strings.Contains(o, "ubuntu") || strings.Contains(o, "debian") || strings.Contains(o, "red hat") || strings.Contains(o, "centos") || strings.Contains(o, "alpine") || strings.Contains(o, "astra"):
		return "server", "OS_LINUX_ASSUMED_SERVER"
	}
	return "unknown", "OS_UNRECOGNIZED"
}
