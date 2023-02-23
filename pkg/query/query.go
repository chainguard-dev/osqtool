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
	// Refer to q.value.HasMember() calls in osquery/config/packs.cpp
	Query       string `json:"query"`
	Interval    string `json:"interval,omitempty"`
	Shard       int    `json:"shard,omitempty"`
	Platform    string `json:"platform,omitempty"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`

	Snapshot bool `json:"snapshot,omitempty"`
	Removed  bool `json:"removed,omitempty"`
	DenyList bool `json:"denylist,omitempty"`

	// Custom fields
	ExtendedDescription string   `json:"extended_description,omitempty"` // not an official field
	Value               string   `json:"value,omitempty"`                // not an official field, but used in packs
	Name                string   `json:"-"`
	Tags                []string `json:"-"`

	SingleLineQuery string `json:"-"`
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
				klog.V(1).Infof("found query: %s", path)
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

	name := strings.ReplaceAll(filepath.Base(path), ".sql", "")
	m, err := Parse(name, bs)
	if err != nil {
		return nil, fmt.Errorf("parse: %v", err)
	}

	return m, nil
}

// Render renders query metadata into a string.
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

	if m.Interval != "" {
		lines = append(lines, fmt.Sprintf("-- interval: %s", m.Interval))
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
func Parse(name string, bs []byte) (*Metadata, error) { //nolint: funlen // TODO: split into smaller functions
	// NOTE: The 'name' can be as simple as the file base path
	m := &Metadata{
		Name: name,
	}

	out := []string{}
	for i, line := range bytes.Split(bs, []byte("\n")) {
		s := strings.TrimSuffix(string(line), "\n")

		// Wait a minute buckaroo, are you really trying to parse SQL? Have you considered --flags?
		// This is going to require work.
		before, after, hasComment := strings.Cut(s, "--")

		// " --x"
		if strings.Count(before, `"`)%2 == 1 && strings.Count(after, `"`)%2 == 1 {
			hasComment = false
		}
		// ' --x'
		if strings.Count(before, `'`)%2 == 1 && strings.Count(after, `'`)%2 == 1 {
			hasComment = false
		}

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
			m.Interval = content
		case "platform":
			m.Platform = content
		case "version":
			m.Version = content
		case "tags":
			m.Tags = strings.Split(content, " ")
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

	m.Query = strings.TrimSpace(strings.Join(out, "\n"))

	// Single-line query form
	trimmed := []string{}
	for _, l := range out {
		trimmed = append(trimmed, strings.TrimSpace(l))
	}
	m.SingleLineQuery = strings.TrimSpace(strings.Join(trimmed, " "))

	if !strings.HasSuffix(m.Query, ";") {
		m.Query += ";"
		m.SingleLineQuery += ";"
	}

	if m.Platform != "" {
		return m, nil
	}

	// If the platform field isn't filled in, try to guess via the name
	switch {
	case strings.HasSuffix(m.Name, "linux"):
		m.Platform = "linux"
	case strings.HasSuffix(m.Name, "macos"):
		m.Platform = "darwin"
	case strings.HasSuffix(m.Name, "darwin"):
		m.Platform = "darwin"
	case strings.HasSuffix(m.Name, "posix"):
		m.Platform = "posix"
	case strings.HasSuffix(m.Name, "unix"):
		m.Platform = "posix"
	case strings.HasSuffix(m.Name, "windows"):
		m.Platform = "windows"
	case strings.HasSuffix(m.Name, "win"):
		m.Platform = "windows"
	}

	return m, nil
}
