//go:build !darwin

package managedobserve

import "github.com/kontext-security/kontext/internal/diagnostic"

func authorityIOPolicy(diagnostic.Logger) func() func() { return func() func() { return func() {} } }
