// Package adapters parses explicitly supplied protocol request corpora. These
// importers perform no network I/O and never infer new target scope.
package adapters

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

const MaxCorpusBytes = 1 << 20

type Message struct {
	ID          string `json:"id"`
	ContentType string `json:"content_type"`
	Body        []byte `json:"-"`
	BodySHA256  string `json:"body_sha256"`
}

func GraphQL(data []byte) (Message, error) {
	if len(data) == 0 || len(data) > MaxCorpusBytes {
		return Message{}, fmt.Errorf("GraphQL document must be between 1 and %d bytes", MaxCorpusBytes)
	}
	var doc struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || strings.TrimSpace(doc.Query) == "" {
		return Message{}, fmt.Errorf("GraphQL corpus must be a JSON object with a nonempty query")
	}
	if strings.Contains(doc.Query, "http://") || strings.Contains(doc.Query, "https://") {
		return Message{}, fmt.Errorf("GraphQL document URLs are not target scope")
	}
	return Message{ID: "graphql-explicit-document", ContentType: "application/json", BodySHA256: digest(data)}, nil
}

type WSDLInventory struct {
	Operations []string `json:"operations"`
}

func WSDL(data []byte) (WSDLInventory, error) {
	if len(data) == 0 || len(data) > MaxCorpusBytes {
		return WSDLInventory{}, fmt.Errorf("WSDL exceeds explicit corpus size limit")
	}
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	decoder.Strict = true
	var inventory WSDLInventory
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return inventory, fmt.Errorf("parsing explicit WSDL: %w", err)
		}
		if start, ok := token.(xml.StartElement); ok && start.Name.Local == "operation" {
			for _, attr := range start.Attr {
				if attr.Name.Local == "name" {
					inventory.Operations = append(inventory.Operations, attr.Value)
				}
			}
		}
	}
	return inventory, nil
}

// SOAP validates a bounded explicit SOAP envelope. Endpoint/location attributes
// are deliberately ignored; the explicit target remains the only destination.
func SOAP(data []byte) (Message, error) {
	if len(data) == 0 || len(data) > MaxCorpusBytes {
		return Message{}, fmt.Errorf("SOAP envelope exceeds corpus size limit")
	}
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	envelope := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Message{}, fmt.Errorf("parsing explicit SOAP envelope: %w", err)
		}
		if start, ok := token.(xml.StartElement); ok && start.Name.Local == "Envelope" {
			envelope = true
		}
	}
	if !envelope {
		return Message{}, fmt.Errorf("SOAP corpus must contain an Envelope")
	}
	return Message{ID: "soap-explicit-envelope", ContentType: "text/xml", BodySHA256: digest(data)}, nil
}

func WebSocketMessages(r io.Reader) ([]Message, error) {
	scanner := bufio.NewScanner(io.LimitReader(r, MaxCorpusBytes+1))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	var out []Message
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.Contains(line, "ws://") || strings.Contains(line, "wss://") {
			return nil, fmt.Errorf("WebSocket message corpus cannot create target URIs")
		}
		out = append(out, Message{ID: fmt.Sprintf("websocket-message-%d", len(out)+1), ContentType: "text/plain", BodySHA256: digest([]byte(line))})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func ValidateWebSocketURI(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("WebSocket endpoint must be one explicit absolute ws(s) URI without credentials")
	}
	return u, nil
}

func ReadFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxCorpusBytes {
		return nil, fmt.Errorf("explicit request corpus exceeds %d bytes", MaxCorpusBytes)
	}
	return os.ReadFile(path)
}
