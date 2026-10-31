package oob

import "bytes"

func jsonReader(b []byte) *bytes.Reader {
	return bytes.NewReader(b)
}
