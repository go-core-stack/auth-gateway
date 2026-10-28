// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApiDocsEnabledDefaultConfig(t *testing.T) {
	conf, err := ParseConfig("../../default.yaml")
	if err != nil {
		t.Fatalf("failed to parse default.yaml: %s", err)
	}
	if !conf.IsApiDocsEnabled() {
		t.Fatalf("expected /apidocs/ enabled with default.yaml")
	}
}

func TestApiDocsEnabledFromConfig(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want bool
	}{
		{"key absent", "cors:\n  enabled: true\n", true},
		{"empty section", "apiDocs: {}\n", true},
		{"disabled false", "apiDocs:\n  disabled: false\n", true},
		{"disabled true", "apiDocs:\n  disabled: true\n", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatalf("failed to write config: %s", err)
			}
			conf, err := ParseConfig(path)
			if err != nil {
				t.Fatalf("failed to parse config: %s", err)
			}
			if got := conf.IsApiDocsEnabled(); got != tc.want {
				t.Fatalf("IsApiDocsEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestApiDocsEnabledNoConfigFile(t *testing.T) {
	conf, err := ParseConfig("")
	if err != nil {
		t.Fatalf("failed to parse empty config path: %s", err)
	}
	if !conf.IsApiDocsEnabled() {
		t.Fatalf("expected /apidocs/ enabled with no config file")
	}
}
