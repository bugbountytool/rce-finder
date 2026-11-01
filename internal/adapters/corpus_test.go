package adapters

import (
	"strings"
	"testing"
)

func TestExplicitProtocolCorporaAreBoundedAndDoNotCreateTargets(t *testing.T) {
	graphql, err := GraphQL([]byte(`{"query":"query { viewer { id } }"}`))
	if err != nil || graphql.BodySHA256 == "" {
		t.Fatalf("GraphQL corpus = %#v, %v", graphql, err)
	}
	if _, err := GraphQL([]byte(`{"query":"https://outside.example"}`)); err == nil {
		t.Fatal("GraphQL URL became target metadata")
	}
	wsdl, err := WSDL([]byte(`<definitions><binding><operation name="ExplicitOperation"/></binding></definitions>`))
	if err != nil || len(wsdl.Operations) != 1 {
		t.Fatalf("WSDL = %#v, %v", wsdl, err)
	}
	soap, err := SOAP([]byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><input>canary</input></soap:Body></soap:Envelope>`))
	if err != nil || soap.ContentType != "text/xml" {
		t.Fatalf("SOAP = %#v, %v", soap, err)
	}
	messages, err := WebSocketMessages(strings.NewReader("first\nsecond\n"))
	if err != nil || len(messages) != 2 {
		t.Fatalf("WebSocket corpus = %#v, %v", messages, err)
	}
	if _, err := WebSocketMessages(strings.NewReader("wss://outside.example")); err == nil {
		t.Fatal("WebSocket message created a target")
	}
	if _, err := ValidateWebSocketURI("https://not-websocket.example"); err == nil {
		t.Fatal("invalid WebSocket scheme accepted")
	}
	if _, err := GraphQL([]byte(strings.Repeat("x", MaxCorpusBytes+1))); err == nil {
		t.Fatal("oversize corpus accepted")
	}
}
