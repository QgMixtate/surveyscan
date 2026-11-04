package usercli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"unicode"
)

func safeCell(v any) string {
	if v == nil {
		return "unknown"
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, fmt.Sprint(v))
}
func render(w io.Writer, raw []byte, operation, format string) error {
	if format == "json" {
		_, e := fmt.Fprintln(w, string(raw))
		return e
	}
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil {
		return fail(5, "INVALID_RESPONSE")
	}
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	write := func(values ...any) {
		cells := make([]string, len(values))
		for i, v := range values {
			cells[i] = safeCell(v)
		}
		fmt.Fprintln(table, strings.Join(cells, "\t"))
	}
	switch {
	case strings.HasPrefix(operation, "assets "):
		write("ASSET_UID", "HOSTNAME", "FRESHNESS")
		items, _ := object["items"].([]any)
		if !strings.HasSuffix(operation, "list") {
			items = []any{object}
		}
		for _, item := range items {
			if row, ok := item.(map[string]any); ok {
				write(row["asset_uid"], row["observed_hostname"], row["freshness"])
			}
		}
	case strings.HasPrefix(operation, "sources "):
		write("SOURCE_ID", "KIND", "STATE", "LAST_CONTACT", "LAST_INVENTORY")
		items, _ := object["items"].([]any)
		if !strings.HasSuffix(operation, "list") {
			items = []any{object}
		}
		for _, item := range items {
			if row, ok := item.(map[string]any); ok {
				write(row["source_id"], row["source_kind"], row["state"], row["last_contact_at"], row["last_successful_inventory_at"])
			}
		}
	case strings.HasPrefix(operation, "profiles "):
		config, _ := object["config"].(map[string]any)
		write("SOURCE_ID", "DESIRED", "APPLIED", "HEARTBEAT_SECONDS", "INVENTORY_SECONDS")
		write(object["source_id"], config["profile_revision"], object["applied_revision"], config["heartbeat_seconds"], config["inventory_seconds"])
	case operation == "diagnostics":
		write("ALERT", "SEVERITY", "SOURCE_ID")
		alerts, _ := object["alerts"].([]any)
		for _, item := range alerts {
			if row, ok := item.(map[string]any); ok {
				write(row["code"], row["severity"], row["source_id"])
			}
		}
	case operation == "status":
		write("STATUS")
		write(object["status"])
	default:
		return fail(2, "TABLE_OUTPUT_NOT_SUPPORTED_FOR_COMMAND")
	}
	if cursor, ok := object["next_cursor"].(string); ok {
		write("NEXT_CURSOR", cursor)
	}
	return table.Flush()
}
