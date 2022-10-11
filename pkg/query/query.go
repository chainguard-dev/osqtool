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

// shortQueryLen is the cut-off for when to render a query within a single line.
const shortQueryLen = 80

type Metadata struct {
	// Refer to q.value.HasMember() calls in osquery/config/packs.cpp
	Query       string `json:"query"`
	Interval    int    `json:"interval,omitempty"`
	Shard       int    `json:"shard,omitempty"`
	Platform    string `json:"platform,omitempty"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`

	Snapshot bool `json:"snapshot,omitempty"`
	Removed  bool `json:"removed,omitempty"`
	DenyList bool `json:"denylist,omitempty"`

	// Custom fields
	ExtendedDescription string `json:"extended_description,omitempty"` // not an official field
	Value               string `json:"value,omitempty"`                // not an official field, but used in packs
	Name                string `json:"-"`
	sourcePath          string
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

// Render renders query metadata into a string
func Render(m *Metadata) (string, error) {
	lines := []string{}

	if m.Description != "" {
		lines = append(lines, fmt.Sprintf("-- %s", m.Description))
	}

	// TODO: only add divider when necessary
	lines = append(lines, "--")

	if m.ExtendedDescription != "" {
		for _, ed := range strings.Split(m.ExtendedDescription, "\n") {
			lines = append(lines, fmt.Sprintf("-- %s", ed))
		}
		lines = append(lines, "-- ")
	}

	if m.Interval > 0 {
		lines = append(lines, fmt.Sprintf("-- interval: %d", m.Interval))
	}

	if m.Platform != "" {
		lines = append(lines, fmt.Sprintf("-- platform: %s", m.Platform))
	}

	if m.Shard > 0 {
		lines = append(lines, fmt.Sprintf("-- shard: %d", m.Shard))
	}

	if m.Value != "" {
		lines = append(lines, fmt.Sprintf("-- value: %s", m.Value))
	}

	if m.Version != "" {
		lines = append(lines, fmt.Sprintf("-- version: %s", m.Version))
	}

	lines = append(lines, "")
	lines = append(lines, m.Query)

	return strings.Join(lines, "\n") + "\n", nil
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

	if len(strings.Join(out, "")) > shortQueryLen {
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
