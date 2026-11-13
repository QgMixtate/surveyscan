//go:build linux

package main

import (
	"github.com/QgMixtate/surveyscan/v2/internal/collector"
	"github.com/QgMixtate/surveyscan/v2/internal/collecttargets"
)

// wireTargets подключает цели удалённого сбора из Web (C51.03) к collector.
func wireTargets(relay *collector.Collector) {
	if relay.Config.CredentialState == "" {
		return // без каталога учётных данных (dev-режим без личности) целей нет
	}
	m := &collecttargets.Manager{Post: relay.MachinePost, Listen: relay.Config.Listen, CollectorSource: relay.Claims.Source, CA: relay.Config.CA, StateDir: relay.Config.CredentialState}
	relay.TargetSync = m.Tick
}
