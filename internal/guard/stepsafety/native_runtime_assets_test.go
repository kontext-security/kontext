package stepsafety

import (
	"context"
	"errors"
	"io/fs"
	"testing"
)

type omittedAssetFS struct {
	fs.FS
	name   string
	opened bool
}

func (f *omittedAssetFS) Open(name string) (fs.File, error) {
	if name == f.name {
		f.opened = true
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return f.FS.Open(name)
}

func TestUngatedRuntimeDoesNotLoadRetiredRequestGate(t *testing.T) {
	requireEmbeddedModel(t)
	// Finish singleton initialization before testing a separate asset load.
	nativeTestModel(t)
	previous := agreementModel
	t.Cleanup(func() { agreementModel = previous })
	assets := &omittedAssetFS{FS: nativeAssets, name: "model/native/request_gate.json.gz"}
	model, tokenizer, err := loadNativeRuntime(context.Background(), assets)
	if err != nil || model == nil || tokenizer == nil {
		t.Fatalf("ungated runtime requires retired asset: %v", err)
	}
	if assets.opened {
		t.Fatal("retired request-intent asset was accessed")
	}
	// Action agreement remains a required part of the runtime.
	missingAgreement := &omittedAssetFS{FS: nativeAssets, name: "model/native/agreement.json.gz"}
	if err := loadAgreementAssets(missingAgreement); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing action agreement was accepted: %v", err)
	}
}
