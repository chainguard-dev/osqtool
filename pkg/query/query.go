package query

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"k8s.io/klog/v2"
)

type Metadata struct {
	sourcePath string

	Name            string `json:"-"`
	Query           string `json:"query"`
	Interval        int    `json:"interval,omitempty"`
	Shard           int    `json:"shard,omitempty"`
	Platform        string `json:"platform,omitempty"`
	Version         string `json:"version,omitempty"`
	Description     string `json:"description,omitempty"`
	LongDescription string `json:"long_description,omitempty"` // not an official field
	Value           string `json:"value,omitempty"`
}

// LoadFromDir recursively loads osquery queries from a directory.
func LoadFromDir(path string) (map[string]*Metadata, error) {
	mm := map[string]*Metadata{}

	err := filepath.Walk(path,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if strings.HasSuffix(path, ".sql") {
				klog.Infof("found query: %s", path)
				m, err := Load(path)
				if err != nil {
					return fmt.Errorf("load: %v", err)
				}
				mm[m.Name] = m
			}
			return nil
		})

	return mm, err
}

// Load loads a query from a file.
func Load(path string) (*Metadata, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %v", err)
	}

	m, err := Parse(bs)
	if err != nil {
		return nil, fmt.Errorf("parse: %v", err)
	}

	m.sourcePath = path
	m.Name = strings.ReplaceAll(filepath.Base(path), ".sql", "")
	return m, nil
}

// Parse parses query content and returns a Metadata object.
func Parse(bs []byte) (*Metadata, error) {
	m := &Metadata{}

	out := []string{}
	for i, line := range bytes.Split(bs, []byte("\n")) {
		s := strings.TrimSuffix(string(line), "\n")
		before, after, hasComment := strings.Cut(s, "--")

		if !hasComment {
			out = append(out, s)
			continue
		}

		if !strings.HasPrefix(strings.TrimSpace(s), "--") {
			out = append(out, before)
			continue
		}

		// If we are here, we have a leading comment - check for directives
		if i == 0 {
			m.Description = strings.TrimSpace(after)
		}

		after = strings.TrimSpace(after)
		directive, content, hasDirective := strings.Cut(strings.TrimSpace(after), ":")
		if hasDirective {
			content = strings.TrimSpace(content)
		}

		// See https://github.com/osquery/osquery/blob/4ee0be8000d59742d4fe86d2cb0a6241b79d11ff/osquery/config/packs.cpp
		switch directive {
		case "interval":
			interval, err := strconv.Atoi(content)
			if err != nil {
				return nil, err
			}
			m.Interval = interval
		case "platform":
			m.Platform = content
		case "version":
			m.Version = content
		case "shard":
			shard, err := strconv.Atoi(content)
			if err != nil {
				return nil, err
			}
			m.Shard = shard
		case "value":
			m.Value = content
		}
	}

	if len(bs) > 80 {
		m.Query = strings.TrimSpace(strings.Join(out, "\n"))
	} else {
		// Single-line short queries
		trimmed := []string{}
		for _, l := range out {
			trimmed = append(trimmed, strings.TrimSpace(l))
		}
		m.Query = strings.TrimSpace(strings.Join(trimmed, " "))
	}

	if !strings.HasSuffix(m.Query, ";") {
		m.Query += ";"
	}

	return m, nil
}
