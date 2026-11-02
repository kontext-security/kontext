package codexmanaged

import "github.com/kontext-security/kontext/internal/fsperm"

func readAdminOnly(path string) ([]byte, error) {
	return fsperm.ReadAdminOnly(path)
}
