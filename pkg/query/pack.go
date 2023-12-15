package query

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"k8s.io/klog/v2"
)

type Pack struct {
	Queries   map[string]*Metadata `json:"queries,omitempty"`
	Discovery map[string]*Metadata `json:"discovery,omitempty"`

	// Refer to obj.HasMember() calls in osquery/config/packs.cpp
	Shard    int    `json:"shard,omitempty"`
	Platform string `json:"platform,omitempty"`
	Version  string `json:"version,omitempty"`
	Oncall   string `json:"oncall,omitempty"`
}

// FlattenPacks flattens an array of Pack objects
func FlattenPacks(ps []*Pack) *Pack {
	var c *Pack

	for _, p := range ps {
		for k, v := range p.Queries {
			c.Queries[k] = v
		}
		for k, v := range p.Discovery {
			c.Discovery[k] = v
		}

		c.Shard = p.Shard
		c.Platform = p.Platform
		c.Version = p.Version
		c.Oncall = p.Oncall
	}
	return c
}

type RenderConfig struct {
	SingleQuotes bool
}

// RenderPack renders an osquery pack file from a set of queries.
func RenderPack(pack *Pack, c *RenderConfig) ([]byte, error) {
	out, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return out, err
	}

	// This does not yet handle the case where someone double-quote:
	// a single quote, for example: mdfind.query="item == 'latest'"
	if c.SingleQuotes {
		out = bytes.ReplaceAll(out, []byte(`\"`), []byte("'"))
	}
	out = bytes.ReplaceAll(out, []byte(`\u003e`), []byte(">"))
	out = bytes.ReplaceAll(out, []byte(`\u003c`), []byte("<"))
	out = bytes.ReplaceAll(out, []byte(`\u0026`), []byte("&"))
	return bytes.ReplaceAll(out, []byte(`\n`), []byte(" \\\n    ")), nil
}

// LoadPack loads and parses an osquery pack file.
func LoadPack(path string) (*Pack, error) {
	pack := &Pack{}
	var err error
	var bs []byte

	if path == "-" {
		r := bufio.NewReader(os.Stdin)
		bs, err = io.ReadAll(r)
	} else {
		bs, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read: %v", err)
	}

	// workaround: invalid character '\n' in string escape code
	// replace trailing \<newline> with \<escaped newline>
	bs = bytes.ReplaceAll(bs, []byte("\\\n"), []byte("\\\\n"))

	// workaround: cannot unmarshal number into Go struct field Metadata.queries.interval of type string
	nakedInterval := regexp.MustCompile(`"interval"\s*:\s*(\d+),`)
	bs = nakedInterval.ReplaceAll(bs, []byte("\"interval\": \"$1\","))

	err = json.Unmarshal(bs, pack)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %v", err)
	}

	// Final repairs
	for name, v := range pack.Queries {
		v.Name = name

		if pack.Platform != "" && v.Platform == "" {
			v.Platform = pack.Platform
		}
		v.Query = strings.ReplaceAll(v.Query, "\\n", "\n")

		singles := []string{}
		for _, line := range strings.Split(v.Query, "\n") {
			singles = append(singles, strings.TrimSpace(line))
		}
		v.SingleLineQuery = strings.Join(singles, " ")
	}

	return pack, nil
}

// SaveToDirectory saves a map of queries into a directory.
func SaveToDirectory(mm map[string]*Metadata, destination string) error {
	for name, m := range mm {
		s, err := Render(m)
		if err != nil {
			return fmt.Errorf("render: %v", err)
		}

		bs := []byte(s)
		path := filepath.Join(destination, name+".sql")
		klog.Infof("Writing %d bytes to %s ...", len(bs), path)
		err = os.WriteFile(path, bs, 0o600)
		if err != nil {
			return fmt.Errorf("write file: %v", err)
		}
	}
	return nil
}
