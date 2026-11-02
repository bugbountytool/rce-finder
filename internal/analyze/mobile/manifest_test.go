package mobile

import (
	"encoding/binary"
	"testing"
)

// buildAXML constructs a minimal binary AXML document with the given string
// pool and start elements, sufficient to exercise the parser.
func buildAXML(strs []string, elems []element) []byte {
	var body []byte
	// string pool chunk
	sp := buildStringPool(strs)
	body = append(body, sp...)
	for _, e := range elems {
		body = append(body, buildStartElement(e, strs)...)
	}
	// top-level XML chunk header
	out := make([]byte, 8)
	binary.LittleEndian.PutUint16(out[0:], 0x0003) // RES_XML_TYPE
	binary.LittleEndian.PutUint16(out[2:], 8)      // header size
	binary.LittleEndian.PutUint32(out[4:], uint32(8+len(body)))
	return append(out, body...)
}

func buildStringPool(strs []string) []byte {
	count := len(strs)
	headerSize := 28
	// offsets table
	var dataBuf []byte
	offsets := make([]int, count)
	for i, s := range strs {
		offsets[i] = len(dataBuf)
		// UTF-16: length (2 bytes) + chars + null terminator (2 bytes)
		dataBuf = append(dataBuf, byte(len(s)), 0)
		for _, r := range s {
			dataBuf = append(dataBuf, byte(r), byte(r>>8))
		}
		dataBuf = append(dataBuf, 0, 0)
	}
	stringsStart := headerSize + count*4
	total := stringsStart + len(dataBuf)
	chunk := make([]byte, total)
	binary.LittleEndian.PutUint16(chunk[0:], 0x0001) // string pool
	binary.LittleEndian.PutUint16(chunk[2:], 28)
	binary.LittleEndian.PutUint32(chunk[4:], uint32(total))
	binary.LittleEndian.PutUint32(chunk[8:], uint32(count))
	binary.LittleEndian.PutUint32(chunk[20:], uint32(stringsStart))
	for i, o := range offsets {
		binary.LittleEndian.PutUint32(chunk[28+i*4:], uint32(o))
	}
	copy(chunk[stringsStart:], dataBuf)
	return chunk
}

func buildStartElement(e element, strs []string) []byte {
	idx := func(s string) uint32 {
		for i, v := range strs {
			if v == s {
				return uint32(i)
			}
		}
		return 0xffffffff
	}
	attrCount := len(e.Attrs)
	// header(8) + line/comment(8) + ns/name(8) + attrStart/attrSize/attrCount/...(10) + attrs
	total := 36 + attrCount*20
	chunk := make([]byte, total)
	binary.LittleEndian.PutUint16(chunk[0:], 0x0102) // start element
	binary.LittleEndian.PutUint16(chunk[2:], 16)
	binary.LittleEndian.PutUint32(chunk[4:], uint32(total))
	binary.LittleEndian.PutUint32(chunk[20:], idx(e.Name))
	binary.LittleEndian.PutUint16(chunk[24:], 20) // attrStart (from offset 16)
	binary.LittleEndian.PutUint16(chunk[26:], 20) // attrSize
	binary.LittleEndian.PutUint16(chunk[28:], uint16(attrCount))
	i := 0
	for name, val := range e.Attrs {
		ao := 36 + i*20
		binary.LittleEndian.PutUint32(chunk[ao+4:], idx(name))
		binary.LittleEndian.PutUint32(chunk[ao+8:], idx(val)) // raw string value
		chunk[ao+15] = 0x03                                   // TYPE_STRING
		i++
	}
	return chunk
}

func TestParseManifestAndAnalyze(t *testing.T) {
	strs := []string{"manifest", "application", "activity", "scheme", "data",
		"package", "debuggable", "allowBackup", "usesCleartextTraffic", "name", "exported", "scheme", "host",
		"com.example.app", "true", ".MainActivity", "myapp", "example.com"}
	elems := []element{
		{Name: "manifest", Attrs: map[string]string{"package": "com.example.app"}},
		{Name: "application", Attrs: map[string]string{"debuggable": "true", "allowBackup": "true", "usesCleartextTraffic": "true"}},
		{Name: "activity", Attrs: map[string]string{"name": ".MainActivity", "exported": "true"}},
		{Name: "data", Attrs: map[string]string{"scheme": "myapp", "host": "example.com"}},
	}
	data := buildAXML(strs, elems)
	m, err := ParseManifest(data)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.Package != "com.example.app" {
		t.Fatalf("package = %q", m.Package)
	}
	if !m.Debuggable {
		t.Fatal("debuggable not parsed")
	}
	if len(m.Components) != 1 || m.Components[0].Name != ".MainActivity" {
		t.Fatalf("components = %+v", m.Components)
	}
	fs := AnalyzeManifest(m)
	ids := map[string]bool{}
	for _, f := range fs {
		ids[f.RuleID] = true
	}
	for _, want := range []string{"android-debuggable", "android-allow-backup", "android-cleartext", "android-exported-activity", "android-custom-scheme"} {
		if !ids[want] {
			t.Errorf("rule %s not detected; got %v", want, ids)
		}
	}
}

func TestRejectsPlainXML(t *testing.T) {
	if _, err := ParseManifest([]byte("<?xml version=\"1.0\"?><manifest/>")); err == nil {
		t.Fatal("plain XML accepted; parser must require binary AXML")
	}
}
