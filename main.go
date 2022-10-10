// osquery-packer generates osquery pack files
//
// Copyright 2021 Chainguard, Inc.
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/klog/v2"
)

type Pack struct {
	Queries map[string]QueryMeta
}

type QueryMeta struct {
	Query       string
	Interval    int
	Platform    string
	Version     string
	Description string
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

func emitPack(qs map[string][]byte) ([]byte, error) {
	pack := &Pack{Queries: map[string]QueryMeta{}}

	for k, v := range qs {
		name := filepath.Base(k)
		qm := QueryMeta{
			Query:    string(v),
			Interval: 86400,
		}
		klog.Infof("emit: %q=%s", k, v)
		pack.Queries[name] = qm
	}

	return json.Marshal(pack)
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

	bs, err := emitPack(qs)
	if err != nil {
		klog.Fatalf("emit: %v", err)
	}
	fmt.Println(string(bs))
}
