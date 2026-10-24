package execution

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseInvocationRequest drives the strict ABI parser with arbitrary
// wire bytes. Required properties:
//
//   - never panics, whatever the input
//   - verdict is deterministic: parsing the same bytes twice yields the
//     same accept/reject decision and the same error text
//   - an accepted request also decodes with a permissive parser (the
//     strict rules only ever narrow what a permissive decode accepts —
//     they must never accept what it rejects)
//   - rejections always carry a non-empty message (a silent reject is
//     indistinguishable from a bug on the wire)
//
// Seeds are the shared conformance corpus — accept and reject vectors —
// plus structural boundaries the corpus does not reach (depth, integer
// edges, duplicate keys, raw bytes).
func FuzzParseInvocationRequest(f *testing.F) {
	type vector struct {
		Wire    string `json:"wire"`
		WireB64 string `json:"wire_b64"`
	}
	var corpus struct {
		Vectors []vector `json:"vectors"`
	}
	data, err := os.ReadFile(filepath.Join("testdata", "invocation-abi-conformance", "vectors.json"))
	if err != nil {
		f.Fatalf("read corpus: %v", err)
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		f.Fatalf("parse corpus: %v", err)
	}
	for _, v := range corpus.Vectors {
		if v.Wire != "" {
			f.Add([]byte(v.Wire))
		}
		if v.WireB64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(v.WireB64)
			if err != nil {
				f.Fatalf("corpus wire_b64 does not decode: %v", err)
			}
			f.Add(decoded)
		}
	}
	deep := append(bytes.Repeat([]byte("["), 70), bytes.Repeat([]byte("]"), 70)...)
	for _, seed := range [][]byte{
		{},
		[]byte(`{`),
		append(append([]byte(`{"capability":"system.echo","authority":{"principal":"p"},"arguments":{"n":`), deep...), []byte(`}}`)...),
		[]byte(`{"authority":{"authority_generation":9223372036854775807}}`),
		[]byte(`{"authority":{"authority_generation":-9223372036854775808}}`),
		[]byte(`{"authority":{"authority_generation":9223372036854775808}}`),
		[]byte(`{"authority":{"authority_generation":01}}`),
		[]byte(`{"capability":"a","capability":"b"}`),
		[]byte(`{"mediation":{"middleware_set_digest":"ab"}}`),
		[]byte{0xff, 0xfe, 0x7b},
		[]byte(`{"capability":"system.echo"} trailing`),
		[]byte(`{"capability":"sys\u0074em.echo"}`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, err1 := ParseInvocationRequest(data)
		_, err2 := ParseInvocationRequest(data)
		switch {
		case err1 == nil && err2 != nil:
			t.Fatalf("non-deterministic: %q accepted then rejected: %v", data, err2)
		case err1 != nil && err2 == nil:
			t.Fatalf("non-deterministic: %q rejected (%v) then accepted", data, err1)
		case err1 != nil && err2 != nil && err1.Error() != err2.Error():
			t.Fatalf("non-deterministic error for %q: %q vs %q", data, err1, err2)
		}
		if err1 == nil {
			var any map[string]json.RawMessage
			if jerr := json.Unmarshal(data, &any); jerr != nil {
				t.Fatalf("strict parser accepted %q but a permissive decode rejects it: %v", data, jerr)
			}
		} else if err1.Error() == "" {
			t.Fatalf("rejection with empty message for %q", data)
		}
	})
}
