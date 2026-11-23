//go:build !windows

package main

import (
	"os"
	"syscall"
)

func sensorStopSignal() os.Signal { return syscall.SIGTERM }
