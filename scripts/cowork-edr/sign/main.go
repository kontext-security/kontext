// Sign the internal archive with the existing Cloud KMS key. Private key
// material never leaves KMS; the OpenPGP library constructs the signature.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgpecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const fingerprint = "BBBDFE996C02A0E482F116A6DE2037B4E5CF93B9"

type kmsSigner struct {
	public  *ecdsa.PublicKey
	version string
}

func (s kmsSigner) Public() crypto.PublicKey { return s.public }
func kmsArgs() []string {
	return []string{"--project=spaces-479912", "--location=europe-west1", "--keyring=cowork-edr", "--key=cowork-package-signing", "--quiet"}
}
func gcloud(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gcloud", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("gcloud failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
func (s kmsSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 || len(digest) != sha256.Size {
		return nil, errors.New("KMS signing requires SHA-256")
	}
	// The gcloud asymmetric-sign command hashes input files. OpenPGP has
	// already hashed the archive and its signature trailer, so submit that
	// digest directly using the KMS REST API instead of hashing it twice.
	token, err := gcloud("auth", "print-access-token", "--account=jens@kontext.security")
	if err != nil {
		return nil, err
	}
	table := crc32.MakeTable(crc32.Castagnoli)
	name := "projects/spaces-479912/locations/europe-west1/keyRings/cowork-edr/cryptoKeys/cowork-package-signing/cryptoKeyVersions/" + s.version
	body, err := json.Marshal(map[string]any{"digest": map[string]string{"sha256": base64.StdEncoding.EncodeToString(digest)}, "digestCrc32c": strconv.FormatUint(uint64(crc32.Checksum(digest, table)), 10)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, "https://cloudkms.googleapis.com/v1/"+name+":asymmetricSign", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KMS asymmetricSign returned HTTP %d", response.StatusCode)
	}
	var result struct {
		Signature       string `json:"signature"`
		SignatureCRC32C string `json:"signatureCrc32c"`
		VerifiedDigest  bool   `json:"verifiedDigestCrc32c"`
		Name            string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&result); err != nil {
		return nil, err
	}
	signature, err := base64.StdEncoding.DecodeString(result.Signature)
	if err != nil {
		return nil, err
	}
	if !result.VerifiedDigest || result.Name != name || result.SignatureCRC32C != strconv.FormatUint(uint64(crc32.Checksum(signature, table)), 10) {
		return nil, errors.New("KMS integrity check failed")
	}
	if !ecdsa.VerifyASN1(s.public, digest, signature) {
		return nil, errors.New("KMS signature failed local verification")
	}
	return signature, nil
}

func signArchive(entity *openpgp.Entity, signer crypto.Signer, archive []byte) ([]byte, error) {
	lifetime := uint32(30 * 24 * 60 * 60)
	id := entity.PrimaryKey.KeyId
	sig := &packet.Signature{Version: 4, SigType: packet.SigTypeBinary, PubKeyAlgo: packet.PubKeyAlgoECDSA, Hash: crypto.SHA256, CreationTime: time.Now(), IssuerKeyId: &id, IssuerKeyVersion: 4, IssuerFingerprint: entity.PrimaryKey.Fingerprint, SigLifetimeSecs: &lifetime}
	h := crypto.SHA256.New()
	_, _ = h.Write(archive)
	key := &packet.PrivateKey{PublicKey: *entity.PrimaryKey, PrivateKey: signer}
	// Anthropic's package format forbids notation subpackets, including the
	// library's optional v4 salt notation. KMS ECDSA already uses randomness.
	randomizeViaNotation := false
	if err := sig.Sign(h, key, &packet.Config{NonDeterministicSignaturesViaNotation: &randomizeViaNotation}); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := sig.Serialize(&out); err != nil {
		return nil, err
	}
	if _, err := openpgp.CheckDetachedSignature(openpgp.EntityList{entity}, bytes.NewReader(archive), bytes.NewReader(out.Bytes()), nil); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func run() error {
	archivePath := flag.String("archive", "", "archive to sign")
	publicPath := flag.String("public-key", "", "approved OpenPGP public key")
	version := flag.String("key-version", "1", "existing enabled KMS key version")
	flag.Parse()
	if *archivePath == "" || *publicPath == "" {
		return errors.New("--archive and --public-key are required")
	}
	armored, err := os.ReadFile(*publicPath)
	if err != nil {
		return err
	}
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		return err
	}
	if len(entities) != 1 || strings.ToUpper(hex.EncodeToString(entities[0].PrimaryKey.Fingerprint)) != fingerprint {
		return errors.New("public key does not match Anthropic-approved fingerprint")
	}
	entity := entities[0]
	approved, ok := entity.PrimaryKey.PublicKey.(*pgpecdsa.PublicKey)
	if !ok || entity.PrimaryKey.PubKeyAlgo != packet.PubKeyAlgoECDSA {
		return errors.New("expected approved ECDSA key")
	}
	args := append([]string{"kms", "keys", "versions", "get-public-key", *version}, kmsArgs()...)
	publicPEM, err := gcloud(args...)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(publicPEM)
	if block == nil {
		return errors.New("KMS returned no public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	public, ok := parsed.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() || public.X.Cmp(approved.X) != 0 || public.Y.Cmp(approved.Y) != 0 {
		return errors.New("KMS public key differs from Anthropic-approved key")
	}
	archive, err := os.ReadFile(*archivePath)
	if err != nil {
		return err
	}
	sig, err := signArchive(entity, kmsSigner{public: public, version: *version}, archive)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*archivePath+".sig", sig, 0600); err != nil {
		return err
	}
	fmt.Printf("Signed and verified %s.sig with %s (30-day validity)\n", *archivePath, fingerprint)
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
