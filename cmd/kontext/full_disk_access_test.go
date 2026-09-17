package main

import (
	"io/fs"
	"testing"
)

func TestFullDiskAccessResult(t *testing.T) {
	for _, err := range []error{nil, &fs.PathError{Op: "stat", Path: "Mail", Err: fs.ErrPermission}, fs.ErrNotExist, fs.ErrInvalid} {
		got := fullDiskAccessResult(err)
		if err == nil {
			if got == nil || !*got {
				t.Fatal("successful stat is readable")
			}
		} else if _, ok := err.(*fs.PathError); ok {
			if got == nil || *got {
				t.Fatal("permission denied is false")
			}
		} else if got != nil {
			t.Fatal("other stat failures are unknown")
		}
	}
}
