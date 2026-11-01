package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	labfixture "github.com/bugbountytool/rce-finder/labs/fixtures"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "loopback listener for the non-executing lab fixture")
	flag.Parse()
	vulnerable, _ := strconv.ParseBool(os.Getenv("RCE_FINDER_VULNERABLE"))
	oobURL := strings.TrimRight(os.Getenv("RCE_FINDER_FAKE_OOB"), "/")
	if parsed, err := url.Parse(oobURL); oobURL != "" && (err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "") {
		log.Fatal("RCE_FINDER_FAKE_OOB must be an explicit HTTP(S) lab URL")
	}
	client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	fixture := &labfixture.Server{Vulnerable: vulnerable}
	if oobURL != "" {
		fixture.Callback = func(canary string) {
			token := strings.TrimSuffix(canary, ".oob.test")
			req, err := http.NewRequest(http.MethodGet, oobURL+"/callback/"+token, nil)
			if err != nil {
				log.Printf("invalid local OOB callback request: %v", err)
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("local OOB callback failed: %v", err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				log.Printf("local OOB callback returned status %d", resp.StatusCode)
			}
		}
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("non-executing lab fixture listening on %s (vulnerable=%t)", listener.Addr(), vulnerable)
	if err := http.Serve(listener, fixture); err != nil {
		log.Fatal(err)
	}
}
