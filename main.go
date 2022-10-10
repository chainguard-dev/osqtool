// osquery-packer generates osquery pack files
//
// Copyright 2021 Chainguard, Inc.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"k8s.io/klog/v2"
)

type Pack struct {
	Queries map[string]QueryMeta `json:"queries"`
}

type QueryMeta struct {
	Query       string `json:"query"`
	Interval    int    `json:"internal,omitempty"`
	Platform    string `json:"platform,omitempty"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
	Value       string `json:"value,omitempty"`
}

func findQueries(path string) (map[string][]byte, error) {
	qs := map[string][]byte{}

	err := filepath.Walk(path,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if strings.HasSuffix(path, ".sql") {
				klog.Infof("found query: %s", path)
				bs, err := ioutil.ReadFile(path)
				if err != nil {
					return err
				}

				qs[path] = bs
			}
			return nil
		})

	return qs, err
}

func processQueries(qb map[string][]byte) (map[string]QueryMeta, error) {
	qms := map[string]QueryMeta{}
	for k, v := range qb {
		qm := QueryMeta{}

		out := []string{}
		for i, line := range bytes.Split(v, []byte("\n")) {
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
				qm.Description = strings.TrimSpace(after)
			}

			after = strings.TrimSpace(after)
			directive, content, hasDirective := strings.Cut(strings.TrimSpace(after), ":")
			if hasDirective {
				content = strings.TrimSpace(content)
			}
			switch directive {
			case "interval":
				interval, err := strconv.Atoi(content)
				if err != nil {
					return qms, err
				}
				qm.Interval = interval
			case "platform":
				qm.Platform = content
			case "version":
				qm.Version = content
			case "value":
				qm.Value = content
			}
		}

		if len(v) > 80 {
			qm.Query = strings.TrimSpace(strings.Join(out, "\n"))
		} else {
			// Single-line short queries
			trimmed := []string{}
			for _, l := range out {
				trimmed = append(trimmed, strings.TrimSpace(l))
			}
			qm.Query = strings.TrimSpace(strings.Join(trimmed, " "))
		}

		if !strings.HasSuffix(qm.Query, ";") {
			qm.Query = qm.Query + ";"
		}

		name := strings.ReplaceAll(filepath.Base(k), ".sql", "")
		qms[name] = qm
	}

	return qms, nil
}

func emitPack(qs map[string]QueryMeta) ([]byte, error) {
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

func main() {
	path := ""
	if len(os.Args) > 1 {
		path = os.Args[1]
	}

	qs, err := findQueries(path)
	if err != nil {
		klog.Fatalf("find queries: %v", err)
	}

	qms, err := processQueries(qs)
	if err != nil {
		klog.Fatalf("process queries: %v", err)
	}

	bs, err := emitPack(qms)
	if err != nil {
		klog.Fatalf("emit: %v", err)
	}
	fmt.Println(string(bs))
}
