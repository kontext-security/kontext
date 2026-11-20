// Throwaway native messaging host: Chrome spawns it, it speaks the
// 4-byte-length-prefixed JSON protocol on stdio, logs every message,
// and (if KONTEXT_SPIKE_SOCK is reachable) forwards it to a "daemon" socket.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	exe, _ := os.Executable()
	logPath := filepath.Join(filepath.Dir(exe), "host.log")
	if p := os.Getenv("KONTEXT_SPIKE_LOG"); p != "" {
		logPath = p
	}
	lf, _ := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	defer lf.Close()
	fmt.Fprintf(lf, "%s host start pid=%d args=%q\n", time.Now().Format(time.RFC3339Nano), os.Getpid(), os.Args)
	sock := filepath.Join(os.TempDir(), "kontext-spike-daemon.sock")
	for {
		var n uint32
		if err := binary.Read(os.Stdin, binary.NativeEndian, &n); err != nil {
			if err != io.EOF {
				fmt.Fprintf(lf, "read len err: %v\n", err)
			}
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(os.Stdin, buf); err != nil {
			fmt.Fprintf(lf, "read body err: %v\n", err)
			return
		}
		fmt.Fprintf(lf, "%s recv %d bytes: %s\n", time.Now().Format(time.RFC3339Nano), n, buf)
		var m map[string]any
		_ = json.Unmarshal(buf, &m)
		forwarded := false
		if c, err := net.DialTimeout("unix", sock, 300*time.Millisecond); err == nil {
			c.Write(append(buf, '\n'))
			c.Close()
			forwarded = true
		}
		resp := map[string]any{"kind": "ack", "forwarded_to_daemon": forwarded, "host_pid": os.Getpid()}
		if m["kind"] == "ping" {
			resp = map[string]any{"kind": "pong", "sent": m["sent"]}
		}
		out, _ := json.Marshal(resp)
		binary.Write(os.Stdout, binary.NativeEndian, uint32(len(out)))
		os.Stdout.Write(out)
	}
}
