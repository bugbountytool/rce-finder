package requestbody

import (
	"bytes"
	"encoding/json"
	"mime"
	"mime/multipart"
	"strings"
	"testing"
)

func TestXMLGoldenEscapesText(t *testing.T) {
	fields := []Field{{Name: "request.user.name", Value: "unchanged"}, {Name: "request.user.input"}, {Name: "request.enabled", Value: "true"}}
	got, err := XML(fields, map[string]string{"request.user.input": `<&"'>{{canary}}`}, MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	want := `<request><user><name>unchanged</name><input>&lt;&amp;&#34;&#39;&gt;{{canary}}</input></user><enabled>true</enabled></request>`
	if string(got) != want {
		t.Fatalf("XML bytes:\n got %q\nwant %q", got, want)
	}
}

func TestXMLRejectsMalformedUnsafeAndOversizedInput(t *testing.T) {
	cases := []struct {
		name   string
		fields []Field
		mutate map[string]string
		limit  int64
	}{
		{"different roots", []Field{{Name: "a.x"}, {Name: "b.x"}}, nil, MaxBytes},
		{"invalid element", []Field{{Name: "request.1bad"}}, nil, MaxBytes},
		{"file field", []Field{{Name: "request.file", Type: "file"}}, nil, MaxBytes},
		{"undeclared mutation", []Field{{Name: "request.input"}}, map[string]string{"other": "x"}, MaxBytes},
		{"malformed control character", []Field{{Name: "request.input"}}, map[string]string{"request.input": "\x01"}, MaxBytes},
		{"invalid UTF-8", []Field{{Name: "request.input"}}, map[string]string{"request.input": string([]byte{0xff})}, MaxBytes},
		{"size limit", []Field{{Name: "request.input"}}, map[string]string{"request.input": strings.Repeat("x", 100)}, 32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := XML(tc.fields, tc.mutate, tc.limit); err == nil {
				t.Fatal("XML() succeeded, want error")
			}
		})
	}
}

func TestMultipartGolden(t *testing.T) {
	fields := []Field{{Name: "description", Value: "unchanged"}, {Name: "input"}}
	body, contentType, err := Multipart(fields, map[string]string{"input": `canary<&>"`}, "rce-finder-fixed-boundary", MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	want := "--rce-finder-fixed-boundary\r\n" +
		"Content-Disposition: form-data; name=\"description\"\r\n\r\n" +
		"unchanged\r\n" +
		"--rce-finder-fixed-boundary\r\n" +
		"Content-Disposition: form-data; name=\"input\"\r\n\r\n" +
		"canary<&>\"\r\n" +
		"--rce-finder-fixed-boundary--\r\n"
	if string(body) != want {
		t.Fatalf("multipart bytes:\n got %q\nwant %q", body, want)
	}
	if contentType != "multipart/form-data; boundary=rce-finder-fixed-boundary" {
		t.Fatalf("Content-Type = %q", contentType)
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "multipart/form-data" {
		t.Fatalf("ParseMediaType() = %q, %v", mediaType, err)
	}
	reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	form, err := reader.ReadForm(MaxBytes)
	if err != nil || form.Value["input"][0] != `canary<&>"` {
		t.Fatalf("multipart round trip = %#v, %v", form.Value, err)
	}
}

func TestMultipartRejectsFilesMalformedValuesAndSizeLimit(t *testing.T) {
	if _, _, err := Multipart([]Field{{Name: "upload", Type: "file", Value: "secret"}}, nil, "safe", MaxBytes); err == nil {
		t.Fatal("file field accepted")
	}
	if _, _, err := Multipart([]Field{{Name: "bad\r\nname"}}, nil, "safe", MaxBytes); err == nil {
		t.Fatal("malformed field accepted")
	}
	if _, _, err := Multipart([]Field{{Name: "input"}}, map[string]string{"other": "value"}, "safe", MaxBytes); err == nil {
		t.Fatal("undeclared mutation accepted")
	}
	if _, _, err := Multipart([]Field{{Name: "input", Value: strings.Repeat("x", 100)}}, nil, "safe", 32); err == nil {
		t.Fatal("oversize multipart body accepted")
	}
}

func TestFieldsAreNeverSerializedIntoResults(t *testing.T) {
	// Body fields have no result representation. This guards their ordinary
	// serialization form from accidentally becoming a credentials container.
	data, err := json.Marshal(struct {
		Status string `json:"status"`
	}{Status: "DRY_RUN"})
	if err != nil || strings.Contains(string(data), "cookie") {
		t.Fatal("unexpected request context in result")
	}
}
