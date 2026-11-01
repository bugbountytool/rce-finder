package inventory

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/bugbountytool/rce-finder/internal/scope"
)

const maxImportBytes = 16 << 20

// LoadHARJSON reads a local HAR and keeps only request endpoints whose final
// URL is within explicit scope. Cookies, headers, bodies, and redirect entries
// are discarded. No DNS or network operation is performed.
func LoadHARJSON(path string, targets []scope.Target) ([]Endpoint, error) {
	var doc struct {
		Log struct {
			Entries []struct {
				Request struct {
					Method string `json:"method"`
					URL    string `json:"url"`
				} `json:"request"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := readJSON(path, &doc); err != nil {
		return nil, fmt.Errorf("reading HAR: %w", err)
	}
	var out []Endpoint
	for i, entry := range doc.Log.Entries {
		u, err := url.Parse(entry.Request.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("HAR entry %d has an invalid absolute HTTP(S) URL", i+1)
		}
		method := strings.ToUpper(entry.Request.Method)
		if !validMethod(method) {
			return nil, fmt.Errorf("HAR entry %d has unsupported method %q", i+1, entry.Request.Method)
		}
		if inScope(targets, u) {
			out = append(out, Endpoint{Method: method, Path: requestPath(u), Source: "har"})
		}
	}
	sortEndpoints(out)
	return uniqueEndpoints(out), nil
}

// LoadPostmanJSON inventories only literal request URLs. Variables, collection
// auth, scripts, folders, and inherited values are not resolved or executed.
// Explicit targets constrain the result even though Postman is not a scope
// authority.
func LoadPostmanJSON(path string, targets []scope.Target) ([]Endpoint, error) {
	var doc struct {
		Info map[string]json.RawMessage `json:"info"`
		Item []postmanItem              `json:"item"`
	}
	if err := readJSON(path, &doc); err != nil {
		return nil, fmt.Errorf("reading Postman collection: %w", err)
	}
	if doc.Info == nil {
		return nil, fmt.Errorf("Postman collection missing info")
	}
	var out []Endpoint
	var walk func([]postmanItem) error
	walk = func(items []postmanItem) error {
		for _, item := range items {
			if err := walk(item.Item); err != nil {
				return err
			}
			if item.Request == nil {
				continue
			}
			method := strings.ToUpper(item.Request.Method)
			if !validMethod(method) {
				return fmt.Errorf("Postman request has unsupported method %q", item.Request.Method)
			}
			raw, literal, err := item.Request.literalURL()
			if err != nil {
				return err
			}
			if !literal {
				continue
			}
			u, err := url.Parse(raw)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("Postman request has an invalid absolute HTTP(S) URL")
			}
			if inScope(targets, u) {
				out = append(out, Endpoint{Method: method, Path: requestPath(u), Source: "postman"})
			}
		}
		return nil
	}
	if err := walk(doc.Item); err != nil {
		return nil, err
	}
	sortEndpoints(out)
	return uniqueEndpoints(out), nil
}

type postmanItem struct {
	Item    []postmanItem   `json:"item"`
	Request *postmanRequest `json:"request"`
}

type postmanRequest struct {
	Method string          `json:"method"`
	URL    json.RawMessage `json:"url"`
}

func (r *postmanRequest) literalURL() (string, bool, error) {
	var raw string
	if err := json.Unmarshal(r.URL, &raw); err == nil {
		return raw, !strings.Contains(raw, "{{"), nil
	}
	var parsed struct {
		Raw string `json:"raw"`
	}
	if err := json.Unmarshal(r.URL, &parsed); err != nil {
		return "", false, fmt.Errorf("Postman request URL must be a string or URL object")
	}
	return parsed.Raw, parsed.Raw != "" && !strings.Contains(parsed.Raw, "{{"), nil
}

func inScope(targets []scope.Target, u *url.URL) bool {
	for _, target := range targets {
		if scope.ContainsEndpoint(target.URL, u) {
			return true
		}
	}
	return false
}

func requestPath(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

func validMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

func sortEndpoints(out []Endpoint) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			if out[i].Method == out[j].Method {
				return out[i].Source < out[j].Source
			}
			return out[i].Method < out[j].Method
		}
		return out[i].Path < out[j].Path
	})
}

func uniqueEndpoints(in []Endpoint) []Endpoint {
	out := in[:0]
	for _, endpoint := range in {
		if len(out) == 0 || out[len(out)-1] != endpoint {
			out = append(out, endpoint)
		}
	}
	return out
}

func readJSON(path string, dst any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > maxImportBytes {
		return fmt.Errorf("import file exceeds %d-byte limit", maxImportBytes)
	}
	decoder := json.NewDecoder(f)
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	return nil
}
