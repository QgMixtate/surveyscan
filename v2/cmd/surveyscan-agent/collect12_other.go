//go:build !linux

package main

func runCollect12([]string) (bool, error) { return false, nil }
