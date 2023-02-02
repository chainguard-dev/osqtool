// osqtool operates on osquery query and pack files
//
// Copyright 2022 Chainguard, Inc.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chainguard-dev/osqtool/pkg/query"
	"github.com/fatih/semgroup"
	"k8s.io/klog/v2"
)

// Config is a struct representation of our flags.
type Config struct {
	maxQueryDuration            time.Duration
	maxQueryDurationPerDay      time.Duration
	MaxTotalQueryDurationPerDay time.Duration
	MinInterval                 time.Duration
	MaxInterval                 time.Duration
	DefaultInterval             time.Duration
	TagIntervals                []string
	Exclude                     []string
	ExcludeTags                 []string
	Platforms                   []string
	Workers                     int
	MaxResults                  int
	SingleQuotes                bool
	MultiLine                   bool
}

func main() {
	outputFlag := flag.String("output", "", "Location of output")
	minIntervalFlag := flag.Duration("max-interval", 15*time.Second, "Queries can't be scheduled more often than this")
	multiLineFlag := flag.Bool("multi-line", false, "output queries is multi-line form. This is accepted by osquery, but technically is invalid JSON.")
	defaultIntervalFlag := flag.Duration("default-interval", 1*time.Hour, "Interval to use for queries which do not specify one")
	tagIntervalsFlag := flag.String("tag-intervals", "transient=5m,postmortem=6h,rapid=15s,often=x/4,seldom=2x", "modifiers to the default-interval based on query tags")
	maxIntervalFlag := flag.Duration("min-interval", 24*time.Hour, "Queries cant be scheduled less often than this")
	excludeFlag := flag.String("exclude", "", "Comma-separated list of queries to exclude")
	excludeTagsFlag := flag.String("exclude-tags", "disabled", "Comma-separated list of tags to exclude")
	platformsFlag := flag.String("platforms", "", "Comma-separated list of platforms to include")
	workersFlag := flag.Int("workers", 0, "Number of workers to use when verifying results (0 for automatic)")
	maxResultsFlag := flag.Int("max-results", 250000, "Maximum number of results a query may return during verify")
	singleQuotesFlag := flag.Bool("single-quotes", false, "Render double quotes as single quotes (may corrupt queries)")
	maxQueryDurationFlag := flag.Duration("max-query-duration", 4*time.Second, "Maximum query duration (checked during --verify)")
	maxQueryDurationPerDayFlag := flag.Duration("max-query-daily-duration", 60*time.Minute, "Maximum duration for a single query multiplied by how many times it runs daily (checked during --verify)")
	maxTotalQueryDurationFlag := flag.Duration("max-total-daily-duration", 6*time.Hour, "Maximum total query-duration per day across all queries")
	verifyFlag := flag.Bool("verify", false, "Verify the output")

	klog.InitFlags(nil)
	flag.Parse()
	args := flag.Args()

	if len(args) < 2 {
		klog.Exitf("usage: osqtool [apply|pack|unpack|verify] <path>")
	}

	action := args[0]
	path := args[1]
	var err error
	c := Config{
		maxQueryDuration:            *maxQueryDurationFlag,
		maxQueryDurationPerDay:      *maxQueryDurationPerDayFlag,
		MaxTotalQueryDurationPerDay: *maxTotalQueryDurationFlag,
		MinInterval:                 *minIntervalFlag,
		MaxInterval:                 *maxIntervalFlag,
		MaxResults:                  *maxResultsFlag,
		DefaultInterval:             *defaultIntervalFlag,
		TagIntervals:                strings.Split(*tagIntervalsFlag, ","),
		Exclude:                     strings.Split(*excludeFlag, ","),
		ExcludeTags:                 strings.Split(*excludeTagsFlag, ","),
		Platforms:                   strings.Split(*platformsFlag, ","),
		Workers:                     *workersFlag,
		SingleQuotes:                *singleQuotesFlag,
		MultiLine:                   *multiLineFlag,
	}

	if c.Workers < 1 {
		c.Workers = runtime.NumCPU()
		if *verifyFlag || action == "verify" {
			klog.Infof("automatically setting verify worker count to %d", c.Workers)
		}
	}

	if *verifyFlag || action == "verify" {
		if _, err := exec.LookPath("osqueryi"); err != nil {
			klog.Exit(fmt.Errorf("osqueryi executable not found on the host! Download it from: https://osquery.io/downloads"))
		}

		err = Verify(path, c)
		if err != nil {
			klog.Exitf("verify failed: %v", err)
		}
	}

	switch action {
	case "apply":
		err = Apply(path, *outputFlag, c)
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

// calculateInterval calculates the default interval to use for a query.
func calculateInterval(m *query.Metadata, c Config) int {
	tagMap := map[string]bool{}
	for _, t := range m.Tags {
		tagMap[t] = true
	}

	interval := int(c.DefaultInterval.Seconds())

	for _, k := range c.TagIntervals {
		tag, modifier, found := strings.Cut(k, "=")
		klog.V(1).Infof("processing tag interval: %s=%s (map: %v) - currently: %d", tag, modifier, tagMap, interval)

		if !found {
			klog.Errorf("unparseable tag interval: %v", k)
			continue
		}

		if !tagMap[tag] {
			klog.V(1).Infof("%s is not mentioned by this query, moving on", tag)
			continue
		}

		if i, err := strconv.Atoi(modifier); err == nil {
			klog.V(1).Infof("setting interval to %d", i)
			interval = i
			continue
		}

		if d, err := time.ParseDuration(modifier); err == nil {
			klog.V(1).Infof("setting interval to %0.f", d.Seconds())
			interval = int(d.Seconds())
			continue
		}

		switch {
		case strings.HasSuffix(modifier, "x"):
			if x, err := strconv.Atoi(modifier); err == nil {
				klog.V(1).Infof("multiplying interval by %d", x)
				interval *= x
			}
		case strings.Contains(modifier, "x/"):
			_, divisor, found := strings.Cut(k, "/")
			if !found {
				klog.Errorf("unparseable tag denominator: %v", k)
				continue
			}

			if d, err := strconv.Atoi(divisor); err == nil {
				klog.V(1).Infof("dividing interval by %d", d)
				interval = int(float32(interval) / float32(d))
			}
		default:
			klog.Errorf("do not understand modifier: %s", k)
		}
	}
	return interval
}

// TODO: Move config application to pkg/query.
func applyConfig(mm map[string]*query.Metadata, c Config) error {
	klog.Infof("applying config: %+v", c)
	minSeconds := int(c.MinInterval.Seconds())
	maxSeconds := int(c.MaxInterval.Seconds())
	excludeMap := map[string]bool{}
	for _, v := range c.Exclude {
		if v == "" {
			continue
		}
		excludeMap[v] = true
	}

	excludeTagsMap := map[string]bool{}
	for _, v := range c.ExcludeTags {
		if v != "" {
			excludeTagsMap[v] = true
		}
	}

	platformsMap := map[string]bool{}
	for _, v := range c.Platforms {
		if v == "" {
			continue
		}

		platformsMap[v] = true
	}

	for name, m := range mm {
		if !c.MultiLine {
			m.Query = m.SingleLineQuery
		}

		if excludeMap[name] {
			klog.Infof("Skipping %s,excluded by --exclude", name)
			delete(mm, name)
			continue
		}

		for _, t := range m.Tags {
			if excludeTagsMap[t] {
				klog.Infof("Skipping %s, excluded by --exclude-tags=%s", name, t)
				delete(mm, name)
				continue
			}
		}

		if len(platformsMap) > 0 && m.Platform != "" && !platformsMap[m.Platform] {
			klog.Infof("Skipping %s - %q not listed in --platforms", name, m.Platform)
			delete(mm, name)
			continue
		}

		if m.Interval == "" {
			interval := calculateInterval(m, c)
			klog.Infof("setting %q interval to %ds", name, interval)
			m.Interval = strconv.Itoa(interval)
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

// Apply applies programattic changes to an osquery pack.
func Apply(sourcePath, output string, c Config) error {
	p, err := query.LoadPack(sourcePath)
	if err != nil {
		return fmt.Errorf("load pack: %v", err)
	}

	if err := applyConfig(p.Queries, c); err != nil {
		return fmt.Errorf("apply: %w", err)
	}

	bs, err := query.RenderPack(p, &query.RenderConfig{SingleQuotes: c.SingleQuotes})
	if err != nil {
		return fmt.Errorf("render: %v", err)
	}

	if output == "" {
		_, err = fmt.Println(string(bs))
		return err
	}

	return os.WriteFile(output, bs, 0o600)
}

// Pack creates an osquery pack from a recursive directory of SQL files.
func Pack(sourcePath, output string, c Config) error {
	mm, err := query.LoadFromDir(sourcePath)
	if err != nil {
		return fmt.Errorf("load from dir: %v", err)
	}

	if err := applyConfig(mm, c); err != nil {
		return fmt.Errorf("apply: %w", err)
	}

	klog.Infof("Packing %d queries into %s ...", len(mm), output)
	bs, err := query.RenderPack(&query.Pack{Queries: mm}, &query.RenderConfig{SingleQuotes: c.SingleQuotes})
	if err != nil {
		return fmt.Errorf("render: %v", err)
	}

	if output == "" {
		_, err = fmt.Println(string(bs))
		return err
	}

	return os.WriteFile(output, bs, 0o600)
}

// Unpack extracts SQL files from an osquery pack.
func Unpack(sourcePath, destPath string, c Config) error {
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

// dailyQueryDuration returns what the total duration for a query would be for a day
func dailyQueryDuration(interval string, d time.Duration) (time.Duration, int, error) {
	i, err := strconv.Atoi(interval)
	if err != nil {
		return time.Duration(0), 0, err
	}

	runs := int(86400 / i)
	return time.Duration(runs) * d, runs, nil
}

// Verify verifies the queries within a directory or pack.
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
	case strings.Contains(path, ".conf"):
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

	var (
		verified, partial, errored uint64
		totalQueryDuration         time.Duration
		totalRuns                  int64
	)

	sg := semgroup.NewGroup(context.Background(), int64(c.Workers))

	for name, m := range mm {
		m := m
		name := name

		sg.Go(func() error {
			klog.Infof("Verifying: %q ", name)
			vf, verr := query.Verify(m)
			if verr != nil {
				klog.Errorf("%q failed validation: %v", name, verr)
				return fmt.Errorf("%s: %w", name, verr)
				errored++
			}

			// Short-circuit out of remaining tests if the query is not compatible with the local platform
			if vf.IncompatiblePlatform != "" {
				atomic.AddUint64(&partial, 1)
				return nil
			}

			if vf.Elapsed > c.maxQueryDuration {
				errored++
				return fmt.Errorf("%q: %s exceeds --max-query-duration=%s", name, vf.Elapsed.Round(time.Millisecond), c.maxQueryDuration)
			}

			queryDurationPerDay, runsPerDay, err := dailyQueryDuration(m.Interval, vf.Elapsed)
			if err != nil {
				errored++
				return fmt.Errorf("%q: failed to parse interval: %v", name, err)
			}

			atomic.AddInt64((*int64)(&totalQueryDuration), int64(queryDurationPerDay))
			atomic.AddInt64((*int64)(&totalRuns), int64(runsPerDay))

			if queryDurationPerDay > c.maxQueryDurationPerDay {
				errored++
				return fmt.Errorf("%q: %s exceeds --max-daily-query-duration=%s (%d runs * %s)", name, queryDurationPerDay.Round(time.Second), c.maxQueryDurationPerDay, runsPerDay, vf.Elapsed.Round(time.Millisecond))
			}

			if len(vf.Results) > c.MaxResults {
				shortResult := []string{}
				for _, r := range vf.Results {
					shortResult = append(shortResult, fmt.Sprintf("%s", r))
				}
				if len(shortResult) >= 10 {
					shortResult = shortResult[0:10]
					shortResult = append(shortResult, "...")
				}

				errored++
				return fmt.Errorf("%q: %d results exceeds --max-results=%d:\n  %s", name, len(vf.Results), c.MaxResults, strings.Join(shortResult, "\n  "))
			}

			klog.Infof("%q returned %d rows in %s, daily cost for interval %s (%d runs): %s", name, len(vf.Results), vf.Elapsed.Round(time.Millisecond), m.Interval, runsPerDay, queryDurationPerDay.Round(time.Second))
			atomic.AddUint64(&verified, 1)
			return nil
		})
	}

	errs := []error{}
	// Someday this might return new go errors
	errs = append(errs, sg.Wait())

	if verified == 0 {
		errs = append(errs, fmt.Errorf("0 queries were fully verified"))
	}

	if totalQueryDuration > c.MaxTotalQueryDurationPerDay {
		errs = append(errs, fmt.Errorf("total query duration per day (%s) exceeds --max-total-daily-duration=%s", totalQueryDuration.Round(time.Second), c.MaxTotalQueryDurationPerDay))
	}

	klog.Infof("%d queries found: %d verified, %d errored, %d partial", len(mm), verified, errored, partial)
	klog.Infof("total daily query runs: %d", totalRuns)
	klog.Infof("total daily execution time: %s", totalQueryDuration)

	return errors.Join(errs...)
}
