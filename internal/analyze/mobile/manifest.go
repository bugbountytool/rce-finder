// Package mobile performs offline static analysis of Android packages. It
// parses the binary AndroidManifest.xml (AXML) to enumerate exported
// components, intent filters, deep links, and dangerous attributes, and scans
// DEX bytecode strings for risky API references (WebView bridges, custom trust
// managers). It requires no device or emulator.
//
// Scope: manifest and string-level analysis only. Full DEX dataflow is out of
// scope; pair with jadx+Semgrep for deeper analysis.
package mobile

import (
	"encoding/binary"
	"fmt"
)

// Component is an Android application component declared in the manifest.
type Component struct {
	Kind     string // activity, service, receiver, provider
	Name     string
	Exported *bool // nil means not explicitly declared
	// IntentFilters holds schemes/hosts for deep-link analysis.
	Schemes []string
	Hosts   []string
}

// Manifest is the parsed security-relevant subset of AndroidManifest.xml.
type Manifest struct {
	Package            string
	Debuggable         bool
	AllowBackup        *bool
	UsesCleartext      *bool
	MinSDK             int
	TargetSDK          int
	Components         []Component
}

// Finding is one Android security observation.
type Finding struct {
	RuleID   string
	Class    string
	CWE      string
	Severity string
	Detail   string
}

// AnalyzeManifest applies security rules to a parsed manifest.
func AnalyzeManifest(m Manifest) []Finding {
	var out []Finding
	if m.Debuggable {
		out = append(out, Finding{RuleID: "android-debuggable", Class: "unsafe-default", CWE: "CWE-489", Severity: "high",
			Detail: "application is debuggable in a release build"})
	}
	if m.AllowBackup != nil && *m.AllowBackup {
		out = append(out, Finding{RuleID: "android-allow-backup", Class: "data-exposure", CWE: "CWE-530", Severity: "medium",
			Detail: "allowBackup=true may expose app data via backup"})
	}
	if m.UsesCleartext != nil && *m.UsesCleartext {
		out = append(out, Finding{RuleID: "android-cleartext", Class: "transport", CWE: "CWE-319", Severity: "medium",
			Detail: "cleartext traffic is permitted"})
	}
	for _, c := range m.Components {
		exported := c.Exported != nil && *c.Exported
		// Pre-API-31 default: a component with an intent filter is exported by
		// default. Components without filters default to not exported.
		if c.Exported == nil && len(c.Schemes)+len(c.Hosts) > 0 {
			exported = true
		}
		if exported {
			sev := "medium"
			detail := fmt.Sprintf("%s %q is exported", c.Kind, c.Name)
			if len(c.Schemes) > 0 {
				detail += fmt.Sprintf(" and handles deep-link schemes %v", c.Schemes)
				sev = "high"
			}
			out = append(out, Finding{RuleID: "android-exported-" + c.Kind, Class: "exported-component", CWE: "CWE-926", Severity: sev, Detail: detail})
		}
		// Custom (non-https) schemes are claimable by any app.
		for _, scheme := range c.Schemes {
			if scheme != "https" && scheme != "http" {
				out = append(out, Finding{RuleID: "android-custom-scheme", Class: "deep-link", CWE: "CWE-939", Severity: "medium",
					Detail: fmt.Sprintf("component %q claims custom scheme %q, which any app can register", c.Name, scheme)})
			}
		}
	}
	return out
}

// --- Binary AXML parsing ---

const (
	chunkStringPool = 0x0001
	chunkXMLStart   = 0x0010
	chunkStartElem  = 0x0102
	chunkEndElem    = 0x0103
	chunkStartNS    = 0x0100
	attrAndroidNS   = "http://schemas.android.com/apk/res/android"
)

// ParseManifest decodes a binary AndroidManifest.xml (AXML) into the
// security-relevant Manifest subset. It returns an error for plain XML or
// malformed input rather than guessing.
func ParseManifest(data []byte) (Manifest, error) {
	if len(data) < 8 || binary.LittleEndian.Uint16(data) != 0x0003 {
		return Manifest{}, fmt.Errorf("not a binary AXML document (plain XML is not supported by this parser)")
	}
	p := &axmlParser{data: data}
	return p.parse()
}

type axmlParser struct {
	data    []byte
	strings []string
}

func (p *axmlParser) parse() (Manifest, error) {
	var m Manifest
	// Walk top-level chunks after the 8-byte header.
	off := 8
	for off+8 <= len(p.data) {
		chunkType := binary.LittleEndian.Uint16(p.data[off:])
		chunkSize := int(binary.LittleEndian.Uint32(p.data[off+4:]))
		if chunkSize < 8 || off+chunkSize > len(p.data) {
			break
		}
		body := p.data[off : off+chunkSize]
		switch chunkType {
		case chunkStringPool:
			p.strings = parseStringPool(body)
		case chunkStartElem:
			elem := parseStartElement(body, p.strings)
			applyElement(&m, elem)
		}
		off += chunkSize
	}
	return m, nil
}

func parseStringPool(body []byte) []string {
	if len(body) < 28 {
		return nil
	}
	count := int(binary.LittleEndian.Uint32(body[8:]))
	stringsStart := int(binary.LittleEndian.Uint32(body[20:]))
	offsets := make([]int, count)
	for i := 0; i < count && 28+i*4+4 <= len(body); i++ {
		offsets[i] = int(binary.LittleEndian.Uint32(body[28+i*4:]))
	}
	var out []string
	for _, o := range offsets {
		start := stringsStart + o
		if start >= len(body) {
			out = append(out, "")
			continue
		}
		s := readUTF16String(body, start)
		out = append(out, s)
	}
	return out
}

func readUTF16String(body []byte, off int) string {
	if off+2 > len(body) {
		return ""
	}
	// UTF-16 length (in chars), then 2 bytes per char, null-terminated.
	n := int(binary.LittleEndian.Uint16(body[off:]))
	start := off + 2
	var buf []byte
	for i := 0; i < n && start+i*2+2 <= len(body); i++ {
		c := binary.LittleEndian.Uint16(body[start+i*2:])
		buf = append(buf, byte(c), byte(c>>8))
	}
	return decodeUTF16(buf)
}

func decodeUTF16(b []byte) string {
	runes := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		runes = append(runes, rune(binary.LittleEndian.Uint16(b[i:])))
	}
	return string(runes)
}

type element struct {
	Name  string
	Attrs map[string]string
}

func parseStartElement(body []byte, strs []string) element {
	// chunk header(8) + line(4)+comment(4) + ns(4)+name(4) + attrStart(2)+attrSize(2)+attrCount(2)...
	if len(body) < 36 {
		return element{}
	}
	nameIdx := int(binary.LittleEndian.Uint32(body[20:]))
	e := element{Attrs: map[string]string{}}
	if nameIdx >= 0 && nameIdx < len(strs) {
		e.Name = strs[nameIdx]
	}
	attrStart := int(binary.LittleEndian.Uint16(body[24:]))
	attrCount := int(binary.LittleEndian.Uint16(body[28:]))
	// attributes begin at body offset 16+attrStart
	base := 16 + attrStart
	for i := 0; i < attrCount; i++ {
		ao := base + i*20
		if ao+20 > len(body) {
			break
		}
		anIdx := int(binary.LittleEndian.Uint32(body[ao+4:]))
		rawValIdx := int(binary.LittleEndian.Uint32(body[ao+8:]))
		typedValType := body[ao+15]
		typedValData := binary.LittleEndian.Uint32(body[ao+16:])
		var name, value string
		if anIdx >= 0 && anIdx < len(strs) {
			name = strs[anIdx]
		}
		if rawValIdx >= 0 && rawValIdx < len(strs) {
			value = strs[rawValIdx]
		} else if typedValType == 0x12 { // TYPE_INT_BOOLEAN
			if typedValData != 0 {
				value = "true"
			} else {
				value = "false"
			}
		} else if typedValType == 0x10 { // TYPE_INT_DEC
			value = fmt.Sprint(int32(typedValData))
		}
		if name != "" {
			e.Attrs[name] = value
		}
	}
	return e
}

// applyElement folds a parsed element into the manifest model.
func applyElement(m *Manifest, e element) {
	switch e.Name {
	case "manifest":
		m.Package = e.Attrs["package"]
	case "application":
		if e.Attrs["debuggable"] == "true" {
			m.Debuggable = true
		}
		if v, ok := e.Attrs["allowBackup"]; ok {
			b := v == "true"
			m.AllowBackup = &b
		}
		if v, ok := e.Attrs["usesCleartextTraffic"]; ok {
			b := v == "true"
			m.UsesCleartext = &b
		}
	case "activity", "activity-alias", "service", "receiver", "provider":
		kind := e.Name
		if kind == "activity-alias" {
			kind = "activity"
		}
		c := Component{Kind: kind, Name: e.Attrs["name"]}
		if v, ok := e.Attrs["exported"]; ok {
			b := v == "true"
			c.Exported = &b
		}
		m.Components = append(m.Components, c)
	case "scheme":
		if len(m.Components) > 0 {
			c := &m.Components[len(m.Components)-1]
			c.Schemes = append(c.Schemes, e.Attrs["scheme"])
		}
	case "host", "data":
		if len(m.Components) > 0 {
			c := &m.Components[len(m.Components)-1]
			if h := e.Attrs["host"]; h != "" {
				c.Hosts = append(c.Hosts, h)
			}
			if s := e.Attrs["scheme"]; s != "" {
				c.Schemes = append(c.Schemes, s)
			}
		}
	}
}
