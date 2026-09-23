//go:build !windows

package main

func platformInfo() {}

func enableVTOutput() func() { return func() {} }
