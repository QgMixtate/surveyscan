package inventory

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
)

// DeviceHint — тип устройства для схемы сети (C22.04) по наблюдаемым фактам: модель оборудования, ОС, службы и ПО
// виртуализации, отсутствие ОС у узла, собранного по SNMP. Пользователь может переопределить тип на схеме.
type DeviceHint struct {
	Class  string // server | workstation | virtual_machine | hypervisor | network | unknown
	Reason string
}

// Признаки гипервизора: службы и ПО (без учёта регистра). Хранится как литерал: SQL собирается без конкатенации.
var hypervisorMarkers = []string{"vmms", "hyper-v", "libvirtd", "qemu-kvm", "proxmox", "pve-manager", "vmware esxi", "xenserver", "xen-hypervisor"}

func (Store) DeviceHints(ctx context.Context, tx pgx.Tx, tenant string, assets []string) (map[string]DeviceHint, error) {
	out := map[string]DeviceHint{}
	if len(assets) == 0 {
		return out, nil
	}
	rows, e := tx.Query(ctx, `SELECT a::text,
(SELECT string_agg(value #>> '{}',' ') FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=a AND section_name='hardware' AND field_name IN ('model','vendor')),
COALESCE((SELECT max(value #>> '{}') FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=a AND section_name='os' AND field_name='name'),
 (SELECT max(value) FROM inventory.current_facts WHERE tenant_id=$1 AND asset_uid=a AND section_name='os' AND fact_key='name')),
EXISTS (SELECT 1 FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=a AND section_name IN ('services','software') AND field_name IN ('name','display_name')
 AND lower(value #>> '{}') LIKE ANY (SELECT '%'||m||'%' FROM unnest($3::text[]) m)),
EXISTS (SELECT 1 FROM inventory.record_section_state12 WHERE tenant_id=$1 AND asset_uid=a AND section_name='os' AND last_status='unsupported')
FROM unnest($2::uuid[]) a`, tenant, assets, hypervisorMarkers)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var asset string
		var hardware, osName *string
		var hypervisor, noOS bool
		if e = rows.Scan(&asset, &hardware, &osName, &hypervisor, &noOS); e != nil {
			return nil, e
		}
		out[asset] = deviceClass(deref(hardware), deref(osName), hypervisor, noOS)
	}
	return out, rows.Err()
}

func deviceClass(hardware, osName string, hypervisor, noOS bool) DeviceHint {
	o := strings.ToLower(osName)
	if hypervisor || strings.Contains(o, "esxi") || strings.Contains(o, "proxmox") {
		return DeviceHint{"hypervisor", "VIRTUALIZATION_HOST_SOFTWARE"}
	}
	if osName == "" && noOS {
		return DeviceHint{"network", "NETWORK_DEVICE_NO_OS"}
	}
	class, reason := classify(hardware, osName)
	return DeviceHint{class, reason}
}
