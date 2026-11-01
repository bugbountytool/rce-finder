// Package requestbody encodes bounded, declarative request bodies. XML and
// multipart bodies support explicitly declared text fields, never raw XML
// substitution or file-upload mutation.
package requestbody

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"mime/multipart"
	"strings"
	"unicode/utf8"
)

const MaxBytes int64 = 1 << 20

// Field is one declared text field. Name is a dotted XML element path for XML
// and a form field name for multipart bodies.
type Field struct {
	Name  string `yaml:"name" json:"name"`
	Value string `yaml:"value,omitempty" json:"value,omitempty"`
	Type  string `yaml:"type,omitempty" json:"type,omitempty"`
}

type xmlNode struct {
	name     string
	value    string
	children []*xmlNode
}

// XML encodes text fields as a single XML document. Mutations replace the
// complete text value of a declared field and are escaped by encoding/xml.
func XML(fields []Field, mutations map[string]string, limit int64) ([]byte, error) {
	roots, err := xmlTree(fields, mutations)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	encoder := xml.NewEncoder(&buf)
	if err := encodeXMLNode(encoder, roots[0]); err != nil {
		return nil, fmt.Errorf("encoding XML text: %w", err)
	}
	if err := encoder.Flush(); err != nil {
		return nil, fmt.Errorf("encoding XML body: %w", err)
	}
	if err := checkSize(int64(buf.Len()), limit); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func xmlTree(fields []Field, mutations map[string]string) ([]*xmlNode, error) {
	if len(fields) == 0 {
		return nil, fmt.Errorf("XML body requires at least one declared text field")
	}
	if len(fields) > 128 {
		return nil, fmt.Errorf("XML body exceeds 128 declared fields")
	}
	declared := make(map[string]bool, len(fields))
	var roots []*xmlNode
	for _, field := range fields {
		if field.Type != "" && field.Type != "text" {
			return nil, fmt.Errorf("XML field %q: only text fields are supported", field.Name)
		}
		if declared[field.Name] {
			return nil, fmt.Errorf("XML field %q is declared more than once", field.Name)
		}
		declared[field.Name] = true
		parts := strings.Split(field.Name, ".")
		for _, part := range parts {
			if !validXMLName(part) {
				return nil, fmt.Errorf("XML field %q has an invalid element path", field.Name)
			}
		}
		value := field.Value
		if replacement, ok := mutations[field.Name]; ok {
			value = replacement
		}
		if !validText(value) {
			return nil, fmt.Errorf("XML field %q contains invalid UTF-8", field.Name)
		}
		nodes := &roots
		var leaf *xmlNode
		for _, part := range parts {
			node := findChild(*nodes, part)
			if node == nil {
				node = &xmlNode{name: part}
				*nodes = append(*nodes, node)
			}
			leaf = node
			nodes = &node.children
		}
		if len(leaf.children) > 0 {
			return nil, fmt.Errorf("XML field %q conflicts with a parent element path", field.Name)
		}
		leaf.value = value
	}
	if len(roots) != 1 {
		return nil, fmt.Errorf("XML fields must share exactly one root element")
	}
	for name := range mutations {
		if !declared[name] {
			return nil, fmt.Errorf("XML mutation field %q is not declared", name)
		}
	}
	return roots, nil
}

func findChild(nodes []*xmlNode, name string) *xmlNode {
	for _, node := range nodes {
		if node.name == name {
			return node
		}
	}
	return nil
}

func validText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' || r == 0x7f {
			return false
		}
	}
	return true
}

func validXMLName(value string) bool {
	if value == "" {
		return false
	}
	for i, r := range value {
		if r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && (r == '-' || r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

func encodeXMLNode(encoder *xml.Encoder, node *xmlNode) error {
	start := xml.StartElement{Name: xml.Name{Local: node.name}}
	if err := encoder.EncodeToken(start); err != nil {
		return err
	}
	if len(node.children) == 0 {
		if err := encoder.EncodeToken(xml.CharData([]byte(node.value))); err != nil {
			return err
		}
	} else {
		for _, child := range node.children {
			if err := encodeXMLNode(encoder, child); err != nil {
				return err
			}
		}
	}
	return encoder.EncodeToken(start.End())
}

// Multipart encodes declared text fields with the supplied boundary. There is
// deliberately no filename, file content, or per-part Content-Type input.
func Multipart(fields []Field, mutations map[string]string, boundary string, limit int64) ([]byte, string, error) {
	if len(fields) == 0 {
		return nil, "", fmt.Errorf("multipart body requires at least one declared text field")
	}
	if len(fields) > 128 {
		return nil, "", fmt.Errorf("multipart body exceeds 128 declared fields")
	}
	declared := make(map[string]bool, len(fields))
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	if err := writer.SetBoundary(boundary); err != nil {
		return nil, "", fmt.Errorf("invalid multipart boundary: %w", err)
	}
	for _, field := range fields {
		if field.Type != "" && field.Type != "text" {
			return nil, "", fmt.Errorf("multipart field %q: only text fields are supported", field.Name)
		}
		if field.Name == "" || strings.ContainsAny(field.Name, "\r\n\x00") {
			return nil, "", fmt.Errorf("multipart field has an invalid name")
		}
		if declared[field.Name] {
			return nil, "", fmt.Errorf("multipart field %q is declared more than once", field.Name)
		}
		declared[field.Name] = true
		value := field.Value
		if replacement, ok := mutations[field.Name]; ok {
			value = replacement
		}
		if !validText(value) {
			return nil, "", fmt.Errorf("multipart field %q contains invalid UTF-8", field.Name)
		}
		if err := writer.WriteField(field.Name, value); err != nil {
			return nil, "", fmt.Errorf("encoding multipart text field: %w", err)
		}
	}
	for name := range mutations {
		if !declared[name] {
			return nil, "", fmt.Errorf("multipart mutation field %q is not declared", name)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", fmt.Errorf("finishing multipart body: %w", err)
	}
	if err := checkSize(int64(buf.Len()), limit); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), writer.FormDataContentType(), nil
}

func checkSize(size, limit int64) error {
	if limit <= 0 {
		limit = MaxBytes
	}
	if size > limit {
		return fmt.Errorf("encoded request body is %d bytes; limit is %d bytes", size, limit)
	}
	return nil
}
