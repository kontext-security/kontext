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

// mdmMode is how an MDM profile takes part in Claude Code's managed settings.
type mdmMode int

const (
	// mdmNone: no profile, or one that only names the default behavior.
	mdmNone mdmMode = iota
	// mdmMerge: the profile adds settings on top of the managed files.
	mdmMerge
	// mdmReplace: the profile replaces the files, or can't be read.
	mdmReplace
)

// mdmMergeBehavior is the managedSourcesBehavior value that keeps the files
// in force beside the profile.
const mdmMergeBehavior = "merge"

// claudeMDMPolicy reports whether an MDM profile replaces Claude Code's
// managed files on this Mac.
func claudeMDMPolicy() bool { return claudeMDM() == mdmReplace }

// claudeMDM reads the Mac's and the user's profiles; the stronger mode wins.
func claudeMDM() mdmMode {
	if runtime.GOOS != "darwin" {
		return mdmNone
	}
	paths := []string{filepath.Join(managedPreferences, claudePreferenceDomain+".plist")}
	if current, err := user.Current(); err == nil {
		paths = append(paths, filepath.Join(managedPreferences, current.Username, claudePreferenceDomain+".plist"))
	}
	mode := mdmNone
	for _, path := range paths {
		mode = max(mode, mdmPlistMode(path))
	}
	return mode
}

// mdmPlistSuppliesPolicy reports whether the profile at path replaces the
// managed files.
func mdmPlistSuppliesPolicy(path string) bool { return mdmPlistMode(path) == mdmReplace }

// mdmPlistMode reads one profile: any key besides managedSourcesBehavior is
// policy, which replaces the files unless the behavior says merge. A profile
// this build can't read replaces them.
func mdmPlistMode(path string) mdmMode {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return mdmNone
		}
		return mdmReplace
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxMDMPlistBytes+1))
	if err != nil || len(data) > maxMDMPlistBytes {
		return mdmReplace
	}
	entries, ok := plistTopEntries(data)
	if !ok {
		return mdmReplace
	}
	policy, merge := false, false
	for _, entry := range entries {
		if entry.key == mdmBehaviorKey {
			merge = entry.str != nil && *entry.str == mdmMergeBehavior
			continue
		}
		policy = true
	}
	switch {
	case !policy:
		return mdmNone
	case merge:
		return mdmMerge
	}
	return mdmReplace
}

// plistEntry is one top-level key, with its value when that is a string.
type plistEntry struct {
	key string
	str *string
}

// plistTopEntries lists the entries of a property list whose top object is a
// dictionary, binary or XML. False means it couldn't be read as one.
func plistTopEntries(data []byte) ([]plistEntry, bool) {
	if bytes.HasPrefix(data, []byte("bplist00")) {
		return binaryPlistTopEntries(data)
	}
	return xmlPlistTopEntries(data)
}

func xmlPlistTopEntries(data []byte) ([]plistEntry, bool) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = false
	depth, inDict := 0, false
	entries := []plistEntry{}
	value := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return entries, inDict
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
			if depth != 3 {
				continue
			}
			switch {
			case t.Name.Local == "key":
				var key string
				if err := decoder.DecodeElement(&key, &t); err != nil {
					return nil, false
				}
				entries = append(entries, plistEntry{key: key})
				value = true
			case value && t.Name.Local == "string":
				var str string
				if err := decoder.DecodeElement(&str, &t); err != nil {
					return nil, false
				}
				entries[len(entries)-1].str = &str
				value = false
			default:
				if err := decoder.Skip(); err != nil {
					return nil, false
				}
				value = false
			}
			depth--
		case xml.EndElement:
			depth--
		}
	}
}

func binaryPlistTopEntries(data []byte) ([]plistEntry, bool) {
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
	// the marker when the nibble is 0xF. A count is checked against the data
	// before it becomes an int, so an overflowing one is refused.
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
		count := uint(data[at+2 : at+2+size])
		if count > uint64(len(data)) {
			return 0, 0, false
		}
		return int(count), at + 2 + size, true
	}
	str := func(ref uint64) (string, bool) {
		at, ok := offset(ref)
		if !ok {
			return "", false
		}
		size, body, ok := length(at)
		if !ok {
			return "", false
		}
		switch data[at] >> 4 {
		case 0x5: // ASCII
			if body+size > len(data) {
				return "", false
			}
			return string(data[body : body+size]), true
		case 0x6: // UTF-16BE
			if size > len(data)/2 || body+2*size > len(data) {
				return "", false
			}
			units := make([]uint16, size)
			for j := range units {
				units[j] = binary.BigEndian.Uint16(data[body+2*j:])
			}
			return string(utf16.Decode(units)), true
		}
		return "", false
	}
	at, ok := offset(top)
	if !ok || data[at]>>4 != 0xD {
		return nil, false
	}
	n, refs, ok := length(at)
	if !ok || n > len(data)/(2*refSize) || refs+2*n*refSize > len(data) {
		return nil, false
	}
	entries := make([]plistEntry, 0, n)
	for i := range n {
		key, ok := str(uint(data[refs+i*refSize : refs+(i+1)*refSize]))
		if !ok {
			return nil, false
		}
		entry := plistEntry{key: key}
		valueAt := refs + (n+i)*refSize
		if value, ok := str(uint(data[valueAt : valueAt+refSize])); ok {
			entry.str = &value
		}
		entries = append(entries, entry)
	}
	return entries, true
}
