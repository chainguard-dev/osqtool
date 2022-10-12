// osqtool operates on osquery query and pack files
//
// Copyright 2021 Chainguard, Inc.
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"chainguard.dev/osqtool/pkg/query"
	"github.com/hashicorp/go-multierror"

	"k8s.io/klog/v2"
)

type Config struct {
	MaxDuration           time.Duration
	MaxTotalRuntimePerDay time.Duration
	MinInterval           time.Duration
	MaxInterval           time.Duration
	DefaultInterval       time.Duration
	Exclude               []string
	Platforms             []string
}

func main() {
	outputFlag := flag.String("output", "", "Location of output")
	minIntervalFlag := flag.Duration("max-interval", 15*time.Second, "Queries can't be scheduled more often than this")
	defaultIntervalFlag := flag.Duration("default-interval", 1*time.Hour, "Interval to use for queries which do not specify one")
	maxIntervalFlag := flag.Duration("min-interval", 24*time.Hour, "Queries cant be scheduled less often than this")
	excludeFlag := flag.String("exclude", "", "Comma-separated list of queries to exclude")
	platformsFlag := flag.String("platforms", "", "Comma-separated list of platforms to include")

	maxDurationFlag := flag.Duration("max-duration", 4000*time.Millisecond, "Maximum duration (checked during --verify)")
	maxTotalRuntimeFlag := flag.Duration("max-total-runtime-per-day", 10*time.Minute, "Maximum total runtime per day")
	verifyFlag := flag.Bool("verify", false, "Verify the output")

	flag.Parse()
	args := flag.Args()

	if len(args) < 2 {
		klog.Exitf("usage: osqtool [pack|unpack] <path>")
	}

	action := args[0]
	path := args[1]
	var err error
	c := Config{
		MaxDuration:           *maxDurationFlag,
		MaxTotalRuntimePerDay: *maxTotalRuntimeFlag,
		MinInterval:           *minIntervalFlag,
		MaxInterval:           *maxIntervalFlag,
		DefaultInterval:       *defaultIntervalFlag,
		Exclude:               strings.Split(*excludeFlag, ","),
		Platforms:             strings.Split(*platformsFlag, ","),
	}

	if *verifyFlag || action == "verify" {
		err = Verify(path, c)
		if err != nil {
			klog.Exitf("verify failed: %v", err)
		}
	}

	switch action {
	case "pack":
		err = Pack(path, *outputFlag, c)
	case "unpack":
		err = Unpack(path, *outputFlag, c)
	case "verify":
	default:
		err = fmt.Errorf("unknown action")
	}
	if err != nil {
		klog.Exitf("%q failed: %v", action, err)
	}
}

func applyConfig(mm map[string]*query.Metadata, c Config) error {
	klog.Infof("applying config: %+v", c)
	minSeconds := int(c.MinInterval.Seconds())
	maxSeconds := int(c.MaxInterval.Seconds())
	defaultInterval := int(c.DefaultInterval.Seconds())
	excludeMap := map[string]bool{}
	for _, v := range c.Exclude {
		if v == "" {
			continue
		}
		excludeMap[v] = true
	}

	platformsMap := map[string]bool{}
	for _, v := range c.Platforms {
		if v == "" {
			continue
		}

		platformsMap[v] = true
	}

	for name, m := range mm {
		if excludeMap[name] {
			klog.Infof("Skipping %s - excluded by --exclude", name)
			delete(mm, name)
			continue
		}
		if len(platformsMap) > 0 && m.Platform != "" && !platformsMap[m.Platform] {
			klog.Infof("Skipping %s - %q not listed in --platforms", name, m.Platform)
			delete(mm, name)
			continue
		}

		if m.Interval == "" {
			klog.Infof("setting %q interval to %ds", name, defaultInterval)
			m.Interval = strconv.Itoa(defaultInterval)
		}

		i, err := strconv.Atoi(m.Interval)
		if err != nil {
			return fmt.Errorf("%q: failed to parse %q: %w", name, m.Interval, err)
		}

		if i > maxSeconds {
			klog.Infof("overriding %q interval to %ds (max)", name, maxSeconds)
			m.Interval = strconv.Itoa(maxSeconds)
		}
		if i < minSeconds {
			klog.Infof("overriding %q interval to %ds (min)", name, minSeconds)
			m.Interval = strconv.Itoa(minSeconds)
		}
	}
	return nil
}

func Pack(sourcePath string, output string, c Config) error {
	mm, err := query.LoadFromDir(sourcePath)
	if err != nil {
		return fmt.Errorf("load from dir: %v", err)
	}

	if err := applyConfig(mm, c); err != nil {
		return fmt.Errorf("apply: %w", err)
	}

	klog.Infof("Packing %d queries into %s ...", len(mm), output)
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

func Unpack(sourcePath string, destPath string, c Config) error {
	if destPath == "" {
		destPath = "."
	}

	p, err := query.LoadPack(sourcePath)
	if err != nil {
		return fmt.Errorf("load pack: %v", err)
	}

	if err := applyConfig(p.Queries, c); err != nil {
		return fmt.Errorf("apply: %w", err)
	}

	err = query.SaveToDirectory(p.Queries, destPath)
	if err != nil {
		return fmt.Errorf("save to dir: %v", err)
	}

	fmt.Printf("%d queries saved to %s\n", len(p.Queries), destPath)
	return nil
}

func Verify(path string, c Config) error {
	s, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}

	mm := map[string]*query.Metadata{}

	switch {
	case s.IsDir():
		mm, err = query.LoadFromDir(path)
		if err != nil {
			return fmt.Errorf("load from dir: %w", err)
		}
	case strings.HasSuffix(path, ".conf"):
		p, err := query.LoadPack(path)
		if err != nil {
			return fmt.Errorf("load from dir: %w", err)
		}
		mm = p.Queries
	default:
		m, err := query.Load(path)
		if err != nil {
			return fmt.Errorf("load: %w", err)
		}
		mm[m.Name] = m
	}

	if err := applyConfig(mm, c); err != nil {
		return fmt.Errorf("apply: %w", err)
	}

	verified := 0
	skipped := 0
	errored := 0

	totalRuntime := time.Duration(0)

	for name, m := range mm {
		klog.Infof("Verifying %q ...", name)
		vf, verr := query.Verify(m)
		if verr != nil {
			klog.Errorf("%q failed validation: %v", name, verr)
			err = multierror.Append(err, fmt.Errorf("%s: %w", name, verr))
			errored++
			continue
		}

		totalRuntime += vf.Elapsed

		if vf.Elapsed > c.MaxDuration {
			err = multierror.Append(err, fmt.Errorf("%q: %s exceeds maximum duration of %s", name, vf.Elapsed, c.MaxDuration))
		}

		if vf.IncompatiblePlatform != "" {
			klog.Warningf("Skipped %q: incompatible platform: %q", name, vf.IncompatiblePlatform)
			skipped++
			continue
		}

		klog.Infof("%q returned %d rows within %s", name, len(vf.Results), vf.Elapsed)
		verified++
	}

	klog.Infof("%d queries found: %d verified, %d errored, %d skipped", len(mm), verified, errored, skipped)
	klog.Infof("total runtime: %s", totalRuntime)
	if totalRuntime > c.MaxTotalRuntimePerDay {
		err = multierror.Append(err, fmt.Errorf("total runtime per day (%s) exceeds %s", totalRuntime, c.MaxTotalRuntimePerDay))
	}

	if verified == 0 {
		err = multierror.Append(err, fmt.Errorf("0 queries were verified"))
	}

	return err
}
