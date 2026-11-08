// Package machineid возвращает стабильный идентификатор локального хоста для привязки
// постоянного агента. Это признак «тот же ОС-экземпляр», а не секрет и не защита от клона.
package machineid

import (
	"encoding/hex"
	"errors"
	"strings"
)

var ErrUnavailable = errors.New("stable local machine identity unavailable")

// normalize принимает 32 hex-символа (Linux machine-id) либо GUID 8-4-4-4-12 (Windows
// MachineGuid) и возвращает 32 hex в нижнем регистре. Нулевой идентификатор отвергается.
func normalize(raw string) (string, error) {
	id := strings.ToLower(strings.TrimSpace(raw))
	if len(id) == 36 && id[8] == '-' && id[13] == '-' && id[18] == '-' && id[23] == '-' {
		id = id[:8] + id[9:13] + id[14:18] + id[19:23] + id[24:]
	}
	decoded, e := hex.DecodeString(id)
	if e != nil || len(decoded) != 16 || id == strings.Repeat("0", 32) {
		return "", ErrUnavailable
	}
	return id, nil
}
