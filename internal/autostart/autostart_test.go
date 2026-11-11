package autostart

import "testing"

func TestCommandQuotesTheProgram(t *testing.T) {
	if got, want := Command(`C:\Program Files\Kontext\kontextw.exe`), `"C:\Program Files\Kontext\kontextw.exe" managed-observe-daemon`; got != want {
		t.Fatalf("Command = %q, want %q", got, want)
	}
}
