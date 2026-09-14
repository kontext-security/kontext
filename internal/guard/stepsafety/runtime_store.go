package stepsafety

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type runtimeSpec struct {
	Version string
	Archive artifactSpec
	Library artifactSpec
}

func runtimeForPlatform() (runtimeSpec, error) {
	spec, ok := runtimeArtifacts[runtime.GOOS+"/"+runtime.GOARCH]
	if !ok {
		return runtimeSpec{}, errors.New("step-safety ONNX Runtime is unsupported on this platform")
	}
	return spec, nil
}

func runtimeDir(modelDir string) string {
	return filepath.Join(modelDir, "runtime", runtime.GOOS+"-"+runtime.GOARCH)
}

func ValidateRuntimeDir(modelDir string) (string, error) {
	spec, err := runtimeForPlatform()
	if err != nil {
		return "", err
	}
	path := filepath.Join(runtimeDir(modelDir), spec.Library.Name)
	if err := verifyArtifact(path, spec.Library); err != nil {
		return "", err
	}
	return path, nil
}

func verifyArtifact(path string, spec artifactSpec) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("artifact %s is unavailable: %w", spec.Name, err)
	}
	if !info.Mode().IsRegular() || info.Size() != spec.Size {
		return fmt.Errorf("artifact %s has unexpected size", spec.Name)
	}
	hash, err := fileSHA256(path)
	if err != nil || hash != spec.SHA256 {
		return fmt.Errorf("artifact %s failed checksum verification", spec.Name)
	}
	return nil
}

// InstallRuntime is called only by the explicit install command. Daemon
// startup is strictly offline and loads only this checksum-pinned library.
// archivePath supports air-gapped installation; an empty path downloads the
// platform-specific CPU archive from Microsoft's official GitHub release.
func InstallRuntime(ctx context.Context, modelDir, archivePath string) error {
	spec, err := runtimeForPlatform()
	if err != nil {
		return err
	}
	destination := runtimeDir(modelDir)
	if _, err := ValidateRuntimeDir(modelDir); err == nil {
		return nil
	}
	if _, err := os.Stat(destination); err == nil {
		return fmt.Errorf("ONNX Runtime destination exists but is invalid: %s", destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(parent, ".onnx-install-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	if archivePath == "" {
		archivePath = filepath.Join(temporary, spec.Archive.Name)
		if err := downloadRuntime(ctx, spec, archivePath); err != nil {
			return err
		}
	}
	if err := verifyArtifact(archivePath, spec.Archive); err != nil {
		return err
	}
	staged := filepath.Join(temporary, "runtime")
	if err := os.Mkdir(staged, 0o700); err != nil {
		return err
	}
	if err := extractRuntime(archivePath, staged, spec); err != nil {
		return err
	}
	if err := verifyArtifact(filepath.Join(staged, spec.Library.Name), spec.Library); err != nil {
		return err
	}
	provenance, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(staged, "PROVENANCE.json"), append(provenance, '\n'), 0o600); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.Rename(staged, destination)
}

func downloadRuntime(ctx context.Context, spec runtimeSpec, path string) error {
	url := "https://github.com/microsoft/onnxruntime/releases/download/v" + spec.Version + "/" + spec.Archive.Name
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("ONNX Runtime download returned HTTP %d", response.StatusCode)
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(out, io.LimitReader(response.Body, spec.Archive.Size+1))
	closeErr := out.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	if written != spec.Archive.Size {
		return errors.New("ONNX Runtime download has unexpected size")
	}
	return nil
}

func extractRuntime(archivePath, destination string, spec runtimeSpec) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	zipped, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer zipped.Close()
	archive := tar.NewReader(zipped)
	root := spec.Archive.Name[:len(spec.Archive.Name)-len(".tgz")]
	// Explicit allowlist: never extract archive paths or follow its symlinks.
	wanted := map[string]string{
		root + "/lib/" + spec.Library.Name: spec.Library.Name,
		root + "/LICENSE":                  "LICENSE",
		root + "/ThirdPartyNotices.txt":    "ThirdPartyNotices.txt",
	}
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name, ok := wanted[header.Name]
		if !ok {
			continue
		}
		limit := int64(4 * 1024 * 1024)
		if name == spec.Library.Name {
			limit = spec.Library.Size
		}
		if header.Typeflag != tar.TypeReg || header.Size < 1 || header.Size > limit {
			return errors.New("unexpected ONNX Runtime archive entry")
		}
		out, err := os.OpenFile(filepath.Join(destination, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, archive)
		if err := errors.Join(copyErr, out.Close()); err != nil {
			return err
		}
		delete(wanted, header.Name)
	}
	if len(wanted) != 0 {
		return errors.New("ONNX Runtime archive is missing required library or license files")
	}
	return nil
}
