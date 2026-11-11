//go:build !windows

package credstore

// Read returns the secret stored under name.
func Read(string) (string, error) { return "", ErrUnsupported }

// Write stores secret under name, replacing what was there.
func Write(string, string) error { return ErrUnsupported }

// Delete removes the secret stored under name.
func Delete(string) error { return ErrUnsupported }
