//go:build windows

package machineid

import "golang.org/x/sys/windows/registry"

// Local читает HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid из 64-битного представления
// реестра (без WOW64-перенаправления). Клон ВМ без sysprep сохраняет тот же MachineGuid.
func Local() (string, error) {
	key, e := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if e != nil {
		return "", ErrUnavailable
	}
	defer key.Close()
	value, _, e := key.GetStringValue("MachineGuid")
	if e != nil || len(value) > 128 {
		return "", ErrUnavailable
	}
	return normalize(value)
}
