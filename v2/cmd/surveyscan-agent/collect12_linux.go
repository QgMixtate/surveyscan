//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/agent"
)

// runCollect12 — разовый локальный сбор секций профиля 1.2 без сети и состояния (диагностика и
// проверка). Печатает JSON {"identity_candidates":[…],"sections":[…]}. Секреты не печатаются.
func runCollect12(args []string) (bool, error) {
	if len(args) == 0 || args[0] != "collect12" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	snap, err := agent.CollectLinux12(ctx)
	if err != nil {
		return true, err
	}
	return true, json.NewEncoder(os.Stdout).Encode(snap)
}
