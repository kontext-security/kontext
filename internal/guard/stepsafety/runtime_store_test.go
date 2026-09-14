package stepsafety

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeExtractionAllowsOnlyPinnedLibraryAndLicenses(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "runtime.tgz")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	zipped := gzip.NewWriter(file)
	archive := tar.NewWriter(zipped)
	spec := runtimeSpec{Archive: artifactSpec{Name: "onnxruntime-test.tgz"}, Library: artifactSpec{Name: "libonnxruntime.so.1", Size: 7, SHA256: sha256String("library")}}
	for name, content := range map[string]string{
		"onnxruntime-test/lib/libonnxruntime.so.1": "library",
		"onnxruntime-test/LICENSE":                 "license",
		"onnxruntime-test/ThirdPartyNotices.txt":   "notices",
		"../../escape":                             "not allowed",
		"onnxruntime-test/lib/unwanted.so":         "not allowed",
	} {
		if err := archive.WriteHeader(&tar.Header{Name: name, Size: int64(len(content)), Mode: 0600}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zipped.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if err := extractRuntime(archivePath, destination, spec); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(destination)
	if err != nil || len(entries) != 3 {
		t.Fatalf("extracted=%v, err=%v", entries, err)
	}
	if err := verifyArtifact(filepath.Join(destination, spec.Library.Name), spec.Library); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination, spec.Library.Name), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyArtifact(filepath.Join(destination, spec.Library.Name), spec.Library); err == nil {
		t.Fatal("tampered runtime passed checksum verification")
	}
}

func TestRuntimePinsCoverReleasePlatforms(t *testing.T) {
	for _, platform := range []string{"darwin/arm64", "darwin/amd64", "linux/arm64", "linux/amd64"} {
		spec, ok := runtimeArtifacts[platform]
		if !ok || spec.Version == "" || spec.Library.Size <= 0 || spec.Archive.Size <= 0 || len(spec.Library.SHA256) != 64 || len(spec.Archive.SHA256) != 64 || !strings.HasSuffix(spec.Archive.Name, ".tgz") {
			t.Fatalf("invalid runtime pin for %s: %+v", platform, spec)
		}
	}
}
