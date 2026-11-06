//go:build windows

package windowsinventory

import (
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strconv"
	"time"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

var errCollectionLimit = errors.New("native collection limit")
var errProviderData = errors.New("native provider data unavailable")

func comCode(err error) uint32 {
	var failure *ole.OleError
	if !errors.As(err, &failure) {
		return 0
	}
	code := uint32(failure.Code())
	if code == 0x80020009 { // DISP_E_EXCEPTION wraps the provider's SCODE.
		switch detail := failure.SubError().(type) {
		case ole.EXCEPINFO:
			code = uint32(detail.SCODE())
		case *ole.EXCEPINFO:
			code = uint32(detail.SCODE())
		}
	}
	return code
}

func providerFailure(err error) (string, string) {
	if errors.Is(err, errCollectionLimit) {
		return "partial", "LIMIT_REACHED"
	}
	switch comCode(err) {
	case 0x80070005, 0x80041003:
		return "unavailable", "ACCESS_DENIED"
	case 0x80040154, 0x8004100e, 0x80041010:
		return "unsupported", "PROVIDER_UNAVAILABLE"
	default:
		return "unavailable", "API_DATA_UNAVAILABLE"
	}
}

func dispatch(program string) (*ole.IUnknown, *ole.IDispatch, error) {
	unknown, err := oleutil.CreateObject(program)
	if err != nil {
		return nil, nil, err
	}
	object, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		unknown.Release()
		return nil, nil, err
	}
	return unknown, object, nil
}

func property(object *ole.IDispatch, name string) (any, error) {
	value, err := oleutil.GetProperty(object, name)
	if err != nil {
		return nil, err
	}
	defer value.Clear()
	return value.Value(), nil
}

// Only fixed, local namespaces and SELECT statements below reach this helper.
// COM may block; this entire function executes in a deadline-killable process.
func wmiRows(namespace, query string, convert func(*ole.IDispatch) (map[string]any, error)) ([]map[string]any, error) {
	unknown, locator, err := dispatch("WbemScripting.SWbemLocator")
	if err != nil {
		return nil, err
	}
	defer unknown.Release()
	defer locator.Release()
	connection, err := oleutil.CallMethod(locator, "ConnectServer", ".", namespace)
	if err != nil {
		return nil, err
	}
	defer connection.Clear()
	service := connection.ToIDispatch()
	if service == nil {
		return nil, errProviderData
	}
	result, err := oleutil.CallMethod(service, "ExecQuery", query, "WQL", 0x30)
	if err != nil {
		return nil, err
	}
	defer result.Clear()
	objects := result.ToIDispatch()
	if objects == nil {
		return nil, errProviderData
	}
	iterator, err := oleutil.GetProperty(objects, "_NewEnum")
	if err != nil {
		return nil, err
	}
	defer iterator.Clear()
	if iterator.ToIUnknown() == nil {
		return nil, errProviderData
	}
	enum, err := iterator.ToIUnknown().IEnumVARIANT(ole.IID_IEnumVariant)
	if err != nil {
		return nil, err
	}
	defer enum.Release()
	rows := []map[string]any{}
	for {
		item, count, err := enum.Next(1)
		if count == 0 {
			if err != nil && comCode(err) != 1 {
				return rows, err
			}
			return rows, nil
		}
		if err != nil {
			item.Clear()
			return rows, err
		}
		object := item.ToIDispatch()
		var row map[string]any
		if object == nil {
			err = errProviderData
		} else {
			row, err = convert(object)
		}
		item.Clear() // Release every enumerated dispatch/variant, not just the set.
		if err != nil {
			return rows, err
		}
		rows = append(rows, row)
		if len(rows) >= 4096 {
			return rows, errCollectionLimit
		}
	}
}

func qfeRows() ([]map[string]any, error) {
	return wmiRows(`ROOT\CIMV2`, "SELECT HotFixID,Description,InstalledOn FROM Win32_QuickFixEngineering", func(object *ole.IDispatch) (map[string]any, error) {
		value, err := property(object, "HotFixID")
		id, ok := value.(string)
		if err != nil || !ok || safeText(id, 128) == "" {
			return nil, errProviderData
		}
		row := map[string]any{"id": id, "source": "qfe"}
		if value, err = property(object, "Description"); err == nil {
			if description, ok := value.(string); ok && safeText(description, 512) != "" {
				row["description"] = description
			}
		}
		// InstalledOn varies by locale/provider, including FILETIME hex strings.
		// Export only an already unambiguous ISO calendar date; never guess.
		if value, err = property(object, "InstalledOn"); err == nil {
			if date, ok := value.(string); ok {
				if parsed, err := time.Parse("2006-01-02", date); err == nil {
					row["installed_on"] = parsed.Format("2006-01-02")
				}
			}
		}
		return row, nil
	})
}

func firewallRows() ([]map[string]any, error) {
	unknown, policy, err := dispatch("HNetCfg.FwPolicy2")
	if err != nil {
		return nil, err
	}
	defer unknown.Release()
	defer policy.Release()
	rows := []map[string]any{}
	for _, profile := range []struct {
		id   int32
		name string
	}{{1, "Domain"}, {2, "Private"}, {4, "Public"}} {
		value, err := oleutil.GetProperty(policy, "FirewallEnabled", profile.id)
		if err != nil {
			return rows, err
		}
		enabled, valid := value.Value().(bool)
		value.Clear()
		if !valid {
			return rows, errProviderData
		}
		rows = append(rows, map[string]any{"kind": "firewall", "name": "Windows Firewall " + profile.name, "provider": "INetFwPolicy2", "enabled": enabled})
	}
	return rows, nil
}

func protectionRows() ([]map[string]any, error) {
	rows, firewallErr := firewallRows()
	defender, defenderErr := wmiRows(`ROOT\Microsoft\Windows\Defender`, "SELECT AntivirusEnabled,AMServiceEnabled,RealTimeProtectionEnabled FROM MSFT_MpComputerStatus", func(object *ole.IDispatch) (map[string]any, error) {
		values := map[string]any{}
		for _, key := range []string{"AntivirusEnabled", "AMServiceEnabled", "RealTimeProtectionEnabled"} {
			if value, err := property(object, key); err == nil {
				if enabled, ok := value.(bool); ok {
					values[key] = enabled
				}
			}
		}
		if len(values) == 0 {
			return nil, errProviderData
		}
		return values, nil
	})
	for _, values := range defender {
		for _, field := range []struct{ key, name string }{{"AntivirusEnabled", "Microsoft Defender antivirus"}, {"AMServiceEnabled", "Microsoft Defender service"}, {"RealTimeProtectionEnabled", "Microsoft Defender real-time protection"}} {
			if enabled, ok := values[field.key]; ok {
				rows = append(rows, map[string]any{"kind": "defender", "name": field.name, "provider": "MSFT_MpComputerStatus", "enabled": enabled})
			}
		}
	}
	antivirus, avErr := wmiRows(`ROOT\SecurityCenter2`, "SELECT displayName,productState FROM AntiVirusProduct", func(object *ole.IDispatch) (map[string]any, error) {
		value, err := property(object, "displayName")
		name, ok := value.(string)
		if err != nil || !ok || safeText(name, 256) == "" {
			return nil, errProviderData
		}
		row := map[string]any{"kind": "antivirus", "name": name, "provider": "SecurityCenter2"}
		if value, err = property(object, "productState"); err == nil {
			var state uint64
			switch n := value.(type) {
			case uint32:
				state = uint64(n)
			case int32:
				if n < 0 {
					return nil, errProviderData
				}
				state = uint64(n)
			default:
				return nil, errProviderData
			}
			row["state"] = "reported_product_state:" + strconv.FormatUint(state, 10)
		}
		return row, nil // ProductState is opaque; do not invent enabled/healthy bits.
	})
	rows = append(rows, antivirus...)
	if len(rows) > 0 {
		if firewallErr != nil || defenderErr != nil || avErr != nil {
			return rows, errors.Join(firewallErr, defenderErr, avErr) // Preserve classification, never export raw error.
		}
		return rows, nil
	}
	for _, err := range []error{firewallErr, defenderErr, avErr} {
		if err != nil {
			return rows, err
		}
	}
	return rows, errProviderData
}

// WriteWorkerSection is a local read-only command. It does not read agent
// configuration, keys, enrollment grants, target credentials or user files.
func WriteWorkerSection(name string, output io.Writer) error {
	if name != "updates" && name != "protection" {
		return ErrWorkerArguments
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	section := failedSection(name, "partial", "BASELINE_COVERAGE_ONLY")
	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err != nil && comCode(err) != 1 {
		section.Status, section.Reason = providerFailure(err)
		return json.NewEncoder(output).Encode(section)
	}
	defer ole.CoUninitialize()
	if name == "updates" {
		section.Records, err = qfeRows()
		section.Reason = "QFE_SUBSET"
	} else {
		section.Records, err = protectionRows()
	}
	if section.Records == nil {
		section.Records = []map[string]any{}
	}
	section.Count = len(section.Records)
	if err != nil {
		section.Status, section.Reason = providerFailure(err)
		if section.Count > 0 {
			section.Status = "partial"
		}
	}
	section.CollectedAt = time.Now().UTC()
	return json.NewEncoder(output).Encode(section)
}
