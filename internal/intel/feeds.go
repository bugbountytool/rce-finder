package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// KEVClient fetches the CISA Known Exploited Vulnerabilities catalog.
type KEVClient struct {
	HTTP *http.Client
	URL  string
}

func NewKEVClient() *KEVClient {
	return &KEVClient{
		HTTP: &http.Client{Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		URL: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
	}
}

type kevFeed struct {
	CatalogVersion string `json:"catalogVersion"`
	Vulnerabilities []struct {
		CveID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

// Fetch returns the set of CVE IDs in the KEV catalog and its version.
func (c *KEVClient) Fetch(ctx context.Context) (map[string]bool, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("kev feed status %d", resp.StatusCode)
	}
	var feed kevFeed
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&feed); err != nil {
		return nil, "", err
	}
	set := map[string]bool{}
	for _, v := range feed.Vulnerabilities {
		set[v.CveID] = true
	}
	return set, feed.CatalogVersion, nil
}

// EPSSClient fetches FIRST EPSS scores.
type EPSSClient struct {
	HTTP *http.Client
	Base string
}

func NewEPSSClient() *EPSSClient {
	return &EPSSClient{
		HTTP: &http.Client{Timeout: 20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		Base: "https://api.first.org/data/v1/epss",
	}
}

type epssResponse struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

// Score returns the EPSS probability and percentile for a CVE. EPSS is a
// 30-day exploitation probability; it must not be multiplied by CVSS or
// treated as a pass/fail threshold.
func (c *EPSSClient) Score(ctx context.Context, cve string) (prob, percentile float64, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+"?cve="+cve, nil)
	if err != nil {
		return 0, 0, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, 0, fmt.Errorf("epss status %d", resp.StatusCode)
	}
	var out epssResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return 0, 0, err
	}
	if len(out.Data) == 0 {
		return 0, 0, fmt.Errorf("no EPSS data for %s", cve)
	}
	prob, _ = strconv.ParseFloat(out.Data[0].EPSS, 64)
	percentile, _ = strconv.ParseFloat(out.Data[0].Percentile, 64)
	return prob, percentile, nil
}
