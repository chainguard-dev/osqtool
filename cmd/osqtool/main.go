// osqtool operates on osquery query and pack files
//
// Copyright 2021 Chainguard, Inc.
package main

import (
	"flag"
	"fmt"
	"os"

	"chainguard.dev/osqtool/pkg/query"

	"k8s.io/klog/v2"
)

var (
	outputFlag = flag.String("output", "", "Location of output")
)

func main() {
	flag.Parse()
	args := flag.Args()

	if len(args) < 2 {
		klog.Exitf("usage: osqtool [pack|unpack] <path>")
	}

	action := args[0]
	path := args[1]
	var err error

	switch action {
	case "pack":
		err = Pack(path, *outputFlag)
	case "unpack":
		err = Unpack(path, *outputFlag)
	default:
		err = fmt.Errorf("unknown action")
	}
	if err != nil {
		klog.Exitf("%q failed: %v", action, err)
	}
}

func Pack(sourcePath string, output string) error {
	mm, err := query.LoadFromDir(sourcePath)
	if err != nil {
		return fmt.Errorf("load from dir: %v", err)
	}

	bs, err := query.RenderPack(mm)
	if err != nil {
		return fmt.Errorf("render: %v", err)
	}

	if output == "" {
		_, err = fmt.Println(string(bs))
		return err
	}

	return os.WriteFile(output, bs, 0o600)
}

func Unpack(sourcePath string, destPath string) error {
	if destPath == "" {
		destPath = "."
	}

	p, err := query.LoadPack(sourcePath)
	if err != nil {
		return fmt.Errorf("load pack: %v", err)
	}

	err = query.SaveToDirectory(p.Queries, destPath)
	if err != nil {
		return fmt.Errorf("save to dir: %v", err)
	}

	fmt.Printf("%d queries saved to %s\n", len(p.Queries), destPath)
	return nil
}
