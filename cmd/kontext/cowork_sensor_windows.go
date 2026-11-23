//go:build windows

package main

import "os"

func sensorStopSignal() os.Signal { return os.Interrupt }
