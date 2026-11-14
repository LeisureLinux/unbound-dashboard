package main

// This file is intentionally minimal: flag parsing is tested through the
// core package (no global flag.CommandLine re-registration inside tests).

import "testing"

func TestVersionIsOverridable(t *testing.T) {
	// Version is a var so -ldflags "-X main.Version=..." works in CI.
	if Version == "" {
		t.Fatal("Version must have a non-empty default")
	}
}
