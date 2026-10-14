package stepsafety

import (
	"compress/gzip"
	"io"
	"runtime"
	"testing"
)

// The tokenizer lives for the whole daemon. A byte trie with a 256-pointer
// array per node held this vocabulary in more than 600 MiB; the map needs
// about 8 MiB.
func TestEmbeddedTokenizerStaysSmall(t *testing.T) {
	f, err := nativeAssets.Open("model/native/tokenizer.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	tok, err := parseTokenizer(data)
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(data)
	runtime.KeepAlive(tok)
	if grown := int64(after.HeapAlloc) - int64(before.HeapAlloc); grown > 64<<20 {
		t.Fatalf("tokenizer holds %d MiB", grown>>20)
	}
}
