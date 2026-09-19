//go:build !darwin

package agentauthority

import (
	"context"
	"os"
)

func readCursor(context.Context, *os.File) (*bool, error) { return nil, nil }
