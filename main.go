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

func processQueries(qb map[string][]byte) map[string]QueryMeta {
	qms := map[string]QueryMeta{}
	for k, v := range qb {
		qm := QueryMeta{}

		out := []string{}
		outTrimmed := []string{}
		for i, line := range bytes.Split(v, []byte("\n")) {
			s := strings.TrimSuffix(string(line), "\n")
			before, after, hasComment := strings.Cut(s, "--")
			if strings.HasPrefix(s, "--") {
				if i == 0 {
					qm.Description = strings.TrimSpace(after)
				}
				continue
			}
			if hasComment {
				out = append(out, before)
				continue
			}
			out = append(out, s)
			outTrimmed = append(outTrimmed, strings.TrimSpace(s))
		}

		if len(v) > 80 {
			qm.Query = strings.TrimSpace(strings.Join(out, "\n"))
		} else {
			qm.Query = strings.TrimSpace(strings.Join(outTrimmed, " "))
		}

		if !strings.HasSuffix(qm.Query, ";") {
			qm.Query = qm.Query + ";"
		}

		name := strings.ReplaceAll(filepath.Base(k), ".sql", "")
		qms[name] = qm
	}

	return qms
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

	qms := processQueries(qs)

	bs, err := emitPack(qms)
	if err != nil {
		klog.Fatalf("emit: %v", err)
	}
	fmt.Println(string(bs))
}
