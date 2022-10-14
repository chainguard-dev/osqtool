package query

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

type VerifyResult struct {
	IncompatiblePlatform string
	Results              []map[string]string
	Elapsed              time.Duration
}

func Verify(m *Metadata) (*VerifyResult, error) {
	incompatible := ""

	if m.Platform != "" && m.Platform != runtime.GOOS {
		if m.Platform == "posix" {
			if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
				incompatible = "posix"
			}
		} else {
			incompatible = m.Platform
		}
	}

	cmd := exec.Command("osqueryi", "--json")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("error: %v", err)
	}

	go func() {
		defer stdin.Close()
		_, err := io.WriteString(stdin, m.Query)
		if err != nil {
			klog.Errorf("failed tos end data to osquery: %w", err)
		}
	}()

	start := time.Now()
	stdout, err := cmd.Output()
	elapsed := time.Since(start)
	klog.Infof("incompatible: %v", incompatible)

	ignoreError := false
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			if incompatible != "" && ee.ExitCode() == 1 && bytes.Contains(ee.Stderr, []byte("no such table:")) {
				klog.Infof("partial test due to incompatible platform %q: %s", incompatible, strings.TrimSpace(string(ee.Stderr)))
				ignoreError = true
			} else {
				return nil, fmt.Errorf("%s [%w]: %s\nstdin: %s", cmd, err, ee.Stderr, m.Query)
			}
		}
		if !ignoreError {
			return nil, fmt.Errorf("%s: %w", cmd, err)
		}
	}

	rows := []map[string]string{}
	err = json.Unmarshal(stdout, &rows)
	if err != nil {
		klog.Errorf("unable to parse output: %v", err)
	}

	return &VerifyResult{IncompatiblePlatform: incompatible, Results: rows, Elapsed: elapsed}, nil
}
