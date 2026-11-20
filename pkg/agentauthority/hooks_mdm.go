package agentauthority

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"unicode/utf16"
)

// managedPreferences is where macOS keeps the preferences MDM profiles force,
// for the Mac and, in a folder per user, for each user.
var managedPreferences = "/Library/Managed Preferences"

const claudePreferenceDomain = "com.anthropic.claudecode"

// mdmBehaviorKey says where Claude Code takes managed settings from; alone it
// supplies no policy, and Claude Code falls through to the managed files.
const mdmBehaviorKey = "managedSourcesBehavior"

// maxMDMPlistBytes bounds the read; a larger profile is taken as policy.
const maxMDMPlistBytes = 1 << 20

// claudeMDMPolicy reports whether an MDM profile forces Claude Code settings
// on this Mac: a profile with any key besides managedSourcesBehavior, or one
// this build can't read.
func claudeMDMPolicy() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	paths := []string{filepath.Join(managedPreferences, claudePreferenceDomain+".plist")}
	if current, err := user.Current(); err == nil {
		paths = append(paths, filepath.Join(managedPreferences, current.Username, claudePreferenceDomain+".plist"))
	}
	for _, path := range paths {
		if mdmPlistSuppliesPolicy(path) {
			return true
		}
	}
	return false
}

func mdmPlistSuppliesPolicy(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return !os.IsNotExist(err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxMDMPlistBytes+1))
	if err != nil || len(data) > maxMDMPlistBytes {
		return true
	}
	keys, ok := plistTopKeys(data)
	if !ok {
		return true
	}
	for _, key := range keys {
		if key != mdmBehaviorKey {
			return true
		}
	}
	return false
}

// plistTopKeys lists the keys of a property list whose top object is a
// dictionary, binary or XML. False means it couldn't be read as one.
func plistTopKeys(data []byte) ([]string, bool) {
	if bytes.HasPrefix(data, []byte("bplist00")) {
		return binaryPlistTopKeys(data)
	}
	return xmlPlistTopKeys(data)
}

func xmlPlistTopKeys(data []byte) ([]string, bool) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = false
	depth, inDict := 0, false
	keys := []string{}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return keys, inDict
		}
		if err != nil {
			return nil, false
		}
		switch t := token.(type) {
		case xml.StartElement:
			depth++
			// <plist><dict>: the top dictionary sits at depth 2.
			if depth == 2 {
				if t.Name.Local != "dict" {
					return nil, false
				}
				inDict = true
			}
			if depth == 3 && t.Name.Local == "key" {
				var key string
				if err := decoder.DecodeElement(&key, &t); err != nil {
					return nil, false
				}
				keys = append(keys, key)
				depth--
			}
		case xml.EndElement:
			depth--
		}
	}
}

func binaryPlistTopKeys(data []byte) ([]string, bool) {
	if len(data) < 8+32 {
		return nil, false
	}
	trailer := data[len(data)-32:]
	offsetSize, refSize := int(trailer[6]), int(trailer[7])
	count := binary.BigEndian.Uint64(trailer[8:16])
	top := binary.BigEndian.Uint64(trailer[16:24])
	table := binary.BigEndian.Uint64(trailer[24:32])
	if offsetSize < 1 || offsetSize > 8 || refSize < 1 || refSize > 8 || top >= count || count > uint64(len(data)) || table > uint64(len(data)) {
		return nil, false
	}
	uint := func(b []byte) uint64 {
		var v uint64
		for _, c := range b {
			v = v<<8 | uint64(c)
		}
		return v
	}
	offset := func(object uint64) (int, bool) {
		start := table + object*uint64(offsetSize)
		if object >= count || start+uint64(offsetSize) > uint64(len(data)) {
			return 0, false
		}
		at := uint(data[start : start+uint64(offsetSize)])
		return int(at), at < uint64(len(data))-32
	}
	// length reads an object's count: the low nibble, or an int object after
	// the marker when the nibble is 0xF.
	length := func(at int) (n, body int, ok bool) {
		info := int(data[at] & 0x0F)
		if info != 0x0F {
			return info, at + 1, true
		}
		if at+1 >= len(data) || data[at+1]>>4 != 0x1 {
			return 0, 0, false
		}
		size := 1 << (data[at+1] & 0x0F)
		if size > 8 || at+2+size > len(data) {
			return 0, 0, false
		}
		return int(uint(data[at+2 : at+2+size])), at + 2 + size, true
	}
	at, ok := offset(top)
	if !ok || data[at]>>4 != 0xD {
		return nil, false
	}
	n, refs, ok := length(at)
	if !ok || refs+n*refSize > len(data) {
		return nil, false
	}
	keys := make([]string, 0, n)
	for i := range n {
		ref := uint(data[refs+i*refSize : refs+(i+1)*refSize])
		keyAt, ok := offset(ref)
		if !ok {
			return nil, false
		}
		size, body, ok := length(keyAt)
		if !ok {
			return nil, false
		}
		switch data[keyAt] >> 4 {
		case 0x5: // ASCII
			if body+size > len(data) {
				return nil, false
			}
			keys = append(keys, string(data[body:body+size]))
		case 0x6: // UTF-16BE
			if body+2*size > len(data) {
				return nil, false
			}
			units := make([]uint16, size)
			for j := range units {
				units[j] = binary.BigEndian.Uint16(data[body+2*j:])
			}
			keys = append(keys, string(utf16.Decode(units)))
		default:
			return nil, false
		}
	}
	return keys, true
}
