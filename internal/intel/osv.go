package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OSVClient queries the OSV API. It is the preferred source for dependency
// matching because OSV uses package identity and range events rather than CPE.
type OSVClient struct {
	HTTP  *http.Client
	Base  string // default https://api.osv.dev
}

func NewOSVClient() *OSVClient {
	return &OSVClient{
		HTTP: &http.Client{Timeout: 20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		Base: "https://api.osv.dev",
	}
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type osvVuln struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Modified  string   `json:"modified"`
	Summary   string   `json:"summary"`
	Affected  []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

// Query returns advisories affecting the given package@version. The caller
// must treat results as applicability matches, not confirmations.
func (c *OSVClient) Query(ctx context.Context, ecosystem, name, version string) ([]Advisory, error) {
	var q osvQuery
	q.Package.Name = name
	q.Package.Ecosystem = ecosystem
	q.Version = version
	body, _ := json.Marshal(q)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+"/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("osv query status %d", resp.StatusCode)
	}
	var out osvQueryResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, err
	}
	var advisories []Advisory
	for _, v := range out.Vulns {
		a := Advisory{ID: v.ID, Aliases: v.Aliases, Summary: v.Summary, Source: "osv"}
		for _, ref := range v.References {
			a.References = append(a.References, ref.URL)
		}
		for _, af := range v.Affected {
			if af.Package.Name == name && af.Package.Ecosystem == ecosystem {
				a.Package = name
				a.Ecosystem = ecosystem
				for _, r := range af.Ranges {
					for _, ev := range r.Events {
						if ev.Introduced != "" {
							a.Introduced = ev.Introduced
						}
						if ev.Fixed != "" {
							a.Fixed = ev.Fixed
						}
						if ev.LastAffected != "" {
							a.LastAffected = ev.LastAffected
						}
					}
				}
			}
		}
		advisories = append(advisories, a)
	}
	return advisories, nil
}
