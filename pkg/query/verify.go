package query

import (
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"time"

	"k8s.io/klog/v2"
)

type VerifyResult struct {
	IncompatiblePlatform string
	Results              []map[string]string
	Elapsed              time.Duration
}

func Verify(m *Metadata) (*VerifyResult, error) {
	if m.Platform != "" && m.Platform != runtime.GOOS {
		if m.Platform == "posix" {
			if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
				return &VerifyResult{IncompatiblePlatform: m.Platform}, nil
			}
		} else {
			return &VerifyResult{IncompatiblePlatform: m.Platform}, nil
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

	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("%s [%w]: %s", cmd, err, ee.Stderr)
		}
		return nil, fmt.Errorf("%s: %w", cmd, err)
	}

	rows := []map[string]string{}
	err = json.Unmarshal(stdout, &rows)
	if err != nil {
		klog.Errorf("unable to parse output: %v", err)
	}

	return &VerifyResult{Results: rows, Elapsed: elapsed}, nil
}
