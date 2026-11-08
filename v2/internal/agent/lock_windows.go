//go:build windows

package agent

import "github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"

// lockState берёт эксклюзивную блокировку писателя над приватным корнем состояния.
// Этот же захват разрешает diskspool.Atomic/RecoverTemps для каталога.
func lockState(directory string) (func(), error) { return diskspool.Lock(directory) }
