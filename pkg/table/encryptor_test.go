// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package table

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-core-stack/core/errors"
)

// keyCase numbers the providers the valid-key case registers, so a
// repeated run (-count=2) never reuses a name the registry already holds.
var keyCase atomic.Int64

func TestNewEncryptorKey(t *testing.T) {
	env := func(key string, set bool) func(string) (string, bool) {
		return func(name string) (string, bool) {
			if name != EncryptorKeyEnvVar {
				t.Fatalf("looked up %q, want %q", name, EncryptorKeyEnvVar)
			}
			return key, set
		}
	}

	// Each case uses its own provider: go-core-stack/core keeps one
	// encryptor per provider per process, with no way to remove one, and
	// init has already tried this package's own.
	t.Run("unset is refused", func(t *testing.T) {
		enc, err := newEncryptor("EncryptorTestUnset", env("", false))
		if enc != nil || !errors.IsInvalidArgument(err) ||
			!strings.Contains(err.Error(), EncryptorKeyEnvVar+" is not set") {
			t.Fatalf("got encryptor %v, error %v; want no encryptor and %q", enc, err, EncryptorKeyEnvVar+" is not set")
		}
	})

	t.Run("empty is refused", func(t *testing.T) {
		enc, err := newEncryptor("EncryptorTestEmpty", env("", true))
		if enc != nil || !errors.IsInvalidArgument(err) ||
			!strings.Contains(err.Error(), "Invalid Key length") {
			t.Fatalf("got encryptor %v, error %v; want no encryptor and the key-length refusal", enc, err)
		}
	})

	t.Run("a key seals and opens", func(t *testing.T) {
		provider := fmt.Sprintf("EncryptorTestKey%d", keyCase.Add(1))
		enc, err := newEncryptor(provider, env("0123456789abcdef0123456789abcdef", true))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sealed, err := enc.EncryptString("secret")
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		opened, err := enc.DecryptString(sealed)
		if err != nil || opened != "secret" {
			t.Fatalf("decrypt: got %q, %v; want \"secret\"", opened, err)
		}
	})
}
