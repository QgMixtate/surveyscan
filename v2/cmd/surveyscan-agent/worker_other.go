//go:build !windows

package main

func runNativeWorker([]string) (bool, error) { return false, nil }
