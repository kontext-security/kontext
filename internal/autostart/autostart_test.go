package autostart

import "testing"

func TestCommandQuotesTheProgram(t *testing.T) {
	if got, want := Command(`C:\Program Files\Kontext\kontextw.exe`), `"C:\Program Files\Kontext\kontextw.exe" managed-observe-daemon`; got != want {
		t.Fatalf("Command = %q, want %q", got, want)
	}
}

func TestProgramIsWhatTheEntryStarts(t *testing.T) {
	for entry, want := range map[string]string{
		Command(`C:\Program Files\Kontext\kontextw.exe`): `C:\Program Files\Kontext\kontextw.exe`,
		`C:\tools\kontextw.exe managed-observe-daemon`:   `C:\tools\kontextw.exe`,
		"": "",
	} {
		if got := Program(entry); got != want {
			t.Errorf("Program(%q) = %q, want %q", entry, got, want)
		}
	}
}
