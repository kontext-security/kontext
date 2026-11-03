//go:build !darwin

package codexmanaged

// readManagedPreferences finds none: only macOS has managed preferences.
func readManagedPreferences() ([]map[string]string, error) { return nil, nil }
