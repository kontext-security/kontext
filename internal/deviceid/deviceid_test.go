package deviceid

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const sampleIoregOutput = `+-o MacBookAir10,1  <class IOPlatformExpertDevice, id 0x100000112, registered, matched, active, busy 0 (2 ms), retain 40>
    {
      "IOPlatformSerialNumber" = "C02XXXXXXXXX"
      "IOPlatformUUID" = "0f3a45b2-1c4d-4e5f-8a9b-0c1d2e3f4a5b"
      "board-id" = <"Mac-XXXX">
    }
`

func stubRunCommand(t *testing.T, fn func(ctx context.Context, name string, args ...string) (string, error)) {
	t.Helper()
	previous := runCommand
	runCommand = fn
	t.Cleanup(func() { runCommand = previous })
}

func TestPlatformUUIDParsesAndUppercasesIoregOutput(t *testing.T) {
	stubRunCommand(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "/usr/sbin/ioreg" {
			t.Fatalf("command = %q, want absolute ioreg path (launchd has a minimal PATH)", name)
		}
		return sampleIoregOutput, nil
	})

	uuid, err := PlatformUUID(context.Background())
	if err != nil {
		t.Fatalf("PlatformUUID() error = %v", err)
	}
	if uuid != "0F3A45B2-1C4D-4E5F-8A9B-0C1D2E3F4A5B" {
		t.Fatalf("PlatformUUID() = %q, want uppercased UUID", uuid)
	}
}

func TestPlatformUUIDErrors(t *testing.T) {
	t.Run("command failure", func(t *testing.T) {
		stubRunCommand(t, func(context.Context, string, ...string) (string, error) {
			return "", errors.New("exec: not found")
		})
		if _, err := PlatformUUID(context.Background()); err == nil {
			t.Fatal("PlatformUUID() error = nil, want command failure surfaced")
		}
	})

	t.Run("uuid absent", func(t *testing.T) {
		stubRunCommand(t, func(context.Context, string, ...string) (string, error) {
			return `{"IOPlatformSerialNumber" = "C02XXXXXXXXX"}`, nil
		})
		if _, err := PlatformUUID(context.Background()); err == nil {
			t.Fatal("PlatformUUID() error = nil, want parse failure")
		}
	})
}

// The expected values are fixed vectors, computed independently. If this test
// fails after touching Key, the derivation changed — which silently detaches
// every already-reported device key from the machines that reported them. Do
// not update the vectors without a hosted-side migration plan.
func TestKeyMatchesFixedVectors(t *testing.T) {
	key, err := Key("0F3A45B2-1C4D-4E5F-8A9B-0C1D2E3F4A5B", "org_katana")
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	if key != "dk_r9NpM1vh94fxqPIcsnx6DalBNVfubPTNYHUBLGUoUcc" {
		t.Fatalf("Key() = %q, want pinned vector", key)
	}

	other, err := Key("0F3A45B2-1C4D-4E5F-8A9B-0C1D2E3F4A5B", "org_other")
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	if other != "dk_wOHaCumCEoXxMGJTl7KiZ-AranWDM3LpSgC8zass4UQ" {
		t.Fatalf("Key() = %q, want pinned vector", other)
	}
	if key == other {
		t.Fatal("same machine in two workspaces derived one key; workspaces must be unlinkable")
	}
}

func TestKeyNormalizesInputCase(t *testing.T) {
	upper, err := Key("0F3A45B2-1C4D-4E5F-8A9B-0C1D2E3F4A5B", "org_katana")
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	lower, err := Key(" 0f3a45b2-1c4d-4e5f-8a9b-0c1d2e3f4a5b ", "org_katana")
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	if upper != lower {
		t.Fatalf("Key() case-sensitive: %q != %q; the same hardware must derive one key", upper, lower)
	}
}

func TestKeyRequiresBothInputs(t *testing.T) {
	if _, err := Key("", "org_katana"); err == nil {
		t.Fatal("Key() with blank UUID = nil error, want refusal")
	}
	if _, err := Key("0F3A45B2-1C4D-4E5F-8A9B-0C1D2E3F4A5B", " "); err == nil {
		t.Fatal("Key() with blank organization id = nil error, want refusal (unkeyed digests are linkable)")
	}
}

func TestKeyShape(t *testing.T) {
	key, err := Key("0F3A45B2-1C4D-4E5F-8A9B-0C1D2E3F4A5B", "org_katana")
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	if !strings.HasPrefix(key, "dk_") {
		t.Fatalf("Key() = %q, want dk_ prefix", key)
	}
	if len(key) != len("dk_")+43 {
		t.Fatalf("len(Key()) = %d, want 3+43 (raw-url base64 of 32 bytes)", len(key))
	}
}
