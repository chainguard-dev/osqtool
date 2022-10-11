package query

import (
	"bytes"
	"encoding/json"
)

type Pack struct {
	Queries map[string]*Metadata `json:"queries"`
}

// RenderPack renders an osquery pack file from a set of queries.
func RenderPack(qs map[string]*Metadata) ([]byte, error) {
	pack := &Pack{Queries: qs}
	out, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return out, err
	}

	// hand massaging the query part for aesthetics
	out = bytes.ReplaceAll(out, []byte(`\u003e`), []byte(">"))
	out = bytes.ReplaceAll(out, []byte(`\u003c`), []byte("<"))
	return bytes.ReplaceAll(out, []byte(`\n`), []byte(" \\\n    ")), nil
}
