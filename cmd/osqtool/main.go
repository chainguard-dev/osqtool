// osquery-packer generates osquery pack files
//
// Copyright 2021 Chainguard, Inc.
package main

import (
	"fmt"
	"os"

	"chainguard.dev/osqtool/pkg/query"

	"k8s.io/klog/v2"
)

func main() {
	path := ""
	if len(os.Args) > 1 {
		path = os.Args[1]
	}

	mm, err := query.LoadFromDir(path)
	if err != nil {
		klog.Fatalf("find queries: %v", err)
	}

	bs, err := query.RenderPack(mm)
	if err != nil {
		klog.Fatalf("emit: %v", err)
	}

	fmt.Println(string(bs))
}
