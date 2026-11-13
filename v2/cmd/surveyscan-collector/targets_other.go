//go:build !linux

package main

import "github.com/QgMixtate/surveyscan/v2/internal/collector"

func wireTargets(*collector.Collector) {}
