package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgpecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestDetachedSignatureWithExternalSigner(t *testing.T) {
	entity, err := openpgp.NewEntity("Internal test", "", "test@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoECDSA, Curve: packet.CurveNistP256})
	if err != nil {
		t.Fatal(err)
	}
	private := entity.PrivateKey.PrivateKey.(*pgpecdsa.PrivateKey)
	signer := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: private.X, Y: private.Y}, D: private.D}
	archive := []byte("synthetic archive bytes")
	signature, err := signArchive(entity, signer, archive)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openpgp.CheckDetachedSignature(openpgp.EntityList{entity}, bytes.NewReader(archive), bytes.NewReader(signature), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := openpgp.CheckDetachedSignature(openpgp.EntityList{entity}, bytes.NewReader(append(archive, '!')), bytes.NewReader(signature), nil); err == nil {
		t.Fatal("accepted changed archive")
	}
	p, err := packet.Read(bytes.NewReader(signature))
	if err != nil {
		t.Fatal(err)
	}
	sig := p.(*packet.Signature)
	if sig.SigType != packet.SigTypeBinary || sig.SigLifetimeSecs == nil || *sig.SigLifetimeSecs != 30*24*60*60 || len(sig.Notations) != 0 || sig.PolicyURI != "" {
		t.Fatalf("unexpected signature constraints: %+v", sig)
	}
}
