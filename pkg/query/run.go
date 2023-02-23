package query

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

type RunResult struct {
	IncompatiblePlatform string
	Rows                 []Row
	Elapsed              time.Duration
}

type Row map[string]string

func (r Row) String() string {
	var sb strings.Builder

	keys := []string{}
	for k := range r {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := r[k]

		text := fmt.Sprintf(`%s:%s `, k, v)
		if strings.Contains(v, " ") || strings.Contains(v, ":") {
			text = fmt.Sprintf(`%s:'%s' `, k, v)
		}

		sb.WriteString(text)
	}

	return strings.TrimSpace(sb.String())
}

// IsIncompatible returns "" if compatible, or a string of the platform this query is compatible with.
func IsIncompatible(m *Metadata) string {
	other := ""
	if m.Platform != "" && m.Platform != runtime.GOOS {
		if m.Platform == "posix" {
			if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
				other = "posix"
			}
		} else {
			other = m.Platform
		}
	}
	return other
}

func Run(m *Metadata) (*RunResult, error) {
	incompatible := IsIncompatible(m)

	cmd := exec.Command("osqueryi", "--json")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("error: %v", err)
	}

	go func() {
		defer stdin.Close()
		_, err := io.WriteString(stdin, m.Query)
		if err != nil {
			klog.Errorf("failed tos end data to osqueryi: %w", err)
		}
	}()

	start := time.Now()
	stdout, err := cmd.Output()
	elapsed := time.Since(start)

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

	rows := []Row{}
	err = json.Unmarshal(stdout, &rows)
	if err != nil {
		klog.Errorf("unable to parse output: %v", err)
	}

	return &RunResult{IncompatiblePlatform: incompatible, Rows: rows, Elapsed: elapsed}, nil
}
