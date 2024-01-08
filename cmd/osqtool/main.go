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
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

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
	minIntervalFlag := flag.Duration("max-interval", 20*time.Second, "Queries can't be scheduled more often than this")
	multiLineFlag := flag.Bool("multi-line", false, "output queries is multi-line form. This is accepted by osquery, but technically is invalid JSON.")
	defaultIntervalFlag := flag.Duration("default-interval", 1*time.Hour, "Interval to use for queries which do not specify one")
	tagIntervalsFlag := flag.String("tag-intervals", "transient=6m,persistent=1.25x,postmortem=6h,rapid=20s,often=x/3,seldom=3x", "modifiers to the default-interval based on query tags")
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
	verifyFlag := flag.Bool("verify", false, "Verify queries quickly")

	klog.InitFlags(nil)
	flag.Parse()
	args := flag.Args()

	if len(args) < 2 {
		klog.Exitf("usage: osqtool [apply|pack|run|unpack|verify] <path>")
	}

	action := args[0]
	paths := args[1:]
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

		err = Verify(paths, c)
		if err != nil {
			klog.Exitf("verify failed: %v", err)
		}
	}

	switch action {
	case "apply":
		err = Apply(paths, *outputFlag, c)
	case "pack":
		err = Pack(paths, *outputFlag, c)
	case "unpack":
		err = Unpack(paths, *outputFlag, c)
	case "verify":
		err = Verify(paths, c)
	case "run":
		err = Run(paths, *outputFlag, c)
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
			klog.V(1).Infof("%s is an int, setting interval to %d", modifier, i)
			interval = i
			continue
		}

		if d, err := time.ParseDuration(modifier); err == nil {
			klog.V(1).Infof("%s is a duration, setting interval to %0.f", modifier, d.Seconds())
			interval = int(d.Seconds())
			continue
		}

		switch {
		case strings.HasSuffix(modifier, "x"):
			x, err := strconv.ParseFloat(strings.Trim(modifier, "x"), 64)
			if err != nil {
				klog.Errorf("unparseable tag multiplier: %v", modifier)
				continue
			}

			klog.V(1).Infof("multiplying interval by %d", x)
			interval = int(float64(interval) * x)
		case strings.Contains(modifier, "x/"):
			_, divisor, found := strings.Cut(k, "/")
			if !found {
				klog.Errorf("unparseable tag denominator: %v", k)
				continue
			}

			if d, err := strconv.ParseFloat(divisor, 64); err == nil {
				klog.V(1).Infof("dividing interval by %d", d)
				interval = int(float64(interval) / d)
			}
		default:
			klog.Errorf("do not understand modifier: %s", k)
		}
	}
	return interval
}

// TODO: Move config application to pkg/query.
func applyConfig(mm map[string]*query.Metadata, c Config) error {
	klog.V(1).Infof("applying config: %+v", c)
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
			klog.V(1).Infof("setting %q interval to %ds", name, interval)
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
func Apply(sourcePaths []string, output string, c Config) error {
	ps := []*query.Pack{}

	for _, path := range sourcePaths {
		p, err := query.LoadPack(path)
		if err != nil {
			return fmt.Errorf("load pack: %v", err)
		}

		if err := applyConfig(p.Queries, c); err != nil {
			return fmt.Errorf("apply: %w", err)
		}
		ps = append(ps, p)
	}

	p := query.FlattenPacks(ps)
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
func Pack(sourcePaths []string, output string, c Config) error {
	mms := map[string]*query.Metadata{}
	for _, path := range sourcePaths {
		klog.Infof("Loading from %s ...", path)
		mm, err := query.LoadFromDir(path)
		if err != nil {
			return fmt.Errorf("load from dir %s: %v", path, err)
		}

		if err := applyConfig(mm, c); err != nil {
			return fmt.Errorf("apply: %w", err)
		}
		for k, v := range mm {
			mms[k] = v
		}
	}

	klog.Infof("Packing %d queries into %s ...", len(mms), output)
	bs, err := query.RenderPack(&query.Pack{Queries: mms}, &query.RenderConfig{SingleQuotes: c.SingleQuotes})
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
func Unpack(sourcePaths []string, destPath string, c Config) error {
	if destPath == "" {
		destPath = "."
	}

	mms := map[string]*query.Metadata{}
	for _, path := range sourcePaths {
		p, err := query.LoadPack(path)
		if err != nil {
			return fmt.Errorf("load pack %s: %v", path, err)
		}

		if err := applyConfig(p.Queries, c); err != nil {
			return fmt.Errorf("apply: %w", err)
		}

		for k, v := range p.Queries {
			mms[k] = v
		}

	}

	err := query.SaveToDirectory(mms, destPath)
	if err != nil {
		return fmt.Errorf("save to dir: %v", err)
	}
	fmt.Printf("%d queries saved to %s\n", len(mms), destPath)
	return nil
}

// dailyQueryDuration returns what the total duration for a query would be for a day.
func dailyQueryDuration(interval string, d time.Duration) (time.Duration, int, error) {
	i, err := strconv.Atoi(interval)
	if err != nil {
		return time.Duration(0), 0, err
	}

	runs := 86400 / i
	return time.Duration(runs) * d, runs, nil
}

func loadAndApply(paths []string, c Config) (map[string]*query.Metadata, error) {
	mm := map[string]*query.Metadata{}

	for _, path := range paths {
		s, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat: %w", err)
		}

		loaded := map[string]*query.Metadata{}
		switch {
		case s.IsDir():
			loaded, err = query.LoadFromDir(path)
			if err != nil {
				return mm, fmt.Errorf("load from dir %s: %w", path, err)
			}
		case strings.Contains(path, ".conf"):
			p, err := query.LoadPack(path)
			if err != nil {
				return mm, fmt.Errorf("load pack %s: %w", path, err)
			}
			loaded = p.Queries
		default:
			m, err := query.Load(path)
			if err != nil {
				return mm, fmt.Errorf("load %s: %w", path, err)
			}
			loaded[m.Name] = m
		}

		for k, v := range loaded {
			if mm[k] != nil {
				return mm, fmt.Errorf("conflict: %q already loaded", k)
			}
			mm[k] = v
		}

		klog.Infof("Loaded %d queries from %s", len(loaded), path)
	}

	klog.Infof("Applying configuration to %d queries: %+v", len(mm), c)
	if err := applyConfig(mm, c); err != nil {
		return mm, fmt.Errorf("apply: %w", err)
	}

	return mm, nil
}

// Run runs the queries within a directory or pack.
func Run(path []string, output string, c Config) error {
	mm, err := loadAndApply(path, c)
	if err != nil {
		return err
	}

	f := os.Stdout
	if output != "" && output != "-" {
		f, err = os.OpenFile(output, os.O_RDWR|os.O_CREATE, 0o700)
		if err != nil {

			return fmt.Errorf("unable to open output: %s", err)
		}
	}

	errs := []error{}
	qs := []*query.Metadata{}
	for _, q := range mm {
		qs = append(qs, q)
	}

	sort.Slice(qs, func(i, j int) bool { return qs[i].Name < qs[j].Name })
	lastRows := -1

	// TODO: Parallelize. Output must be sorted for diffing
	for _, m := range qs {
		m := m
		name := m.Name

		if cw := query.IsIncompatible(m); cw != "" {
			klog.V(1).Infof("skipping incompatible query: %s (%s)", name, cw)
			continue
		}

		vf, verr := query.Run(m)
		if verr != nil {
			klog.Errorf("%q failed: %v", name, verr)
			errs = append(errs, verr)
			continue
		}

		// TODO: Consider CSV output
		header := fmt.Sprintf("%s (%d rows)", name, len(vf.Rows))

		// If this is a big entry after a short entry, add a space
		if lastRows == 0 && len(vf.Rows) > 0 {
			fmt.Fprintln(f, "")
		}
		fmt.Fprintln(f, header)

		lastRows = len(vf.Rows)
		if len(vf.Rows) == 0 {
			continue
		}

		divider := strings.Repeat("-", utf8.RuneCountInString(header))
		fmt.Fprintln(f, divider)
		for _, v := range vf.Rows {
			fmt.Fprintln(f, v)
		}
		fmt.Fprintln(f, "")
	}

	return errors.Join(errs...)
}

// Verify verifies the queries within a directory or pack.
func Verify(path []string, c Config) error {
	mm, err := loadAndApply(path, c)
	if err != nil {
		return err
	}

	var (
		verified, partial  uint64
		totalQueryDuration time.Duration
		totalRuns          int64
	)

	sg := semgroup.NewGroup(context.Background(), int64(c.Workers))

	for name, m := range mm {
		m := m
		name := name

		sg.Go(func() error {
			klog.Infof("Verifying: %q ", name)
			vf, verr := query.Run(m)
			if verr != nil {
				klog.Errorf("%q failed validation: %v", name, verr)
				return fmt.Errorf("%s: %w", name, verr)
			}

			// Short-circuit out of remaining tests if the query is not compatible with the local platform
			if vf.IncompatiblePlatform != "" {
				atomic.AddUint64(&partial, 1)
				return nil
			}

			if vf.Elapsed > c.maxQueryDuration {
				return fmt.Errorf("%q: %s exceeds --max-query-duration=%s", name, vf.Elapsed.Round(time.Millisecond), c.maxQueryDuration)
			}

			queryDurationPerDay, runsPerDay, err := dailyQueryDuration(m.Interval, vf.Elapsed)
			if err != nil {
				return fmt.Errorf("%q: failed to parse interval: %v", name, err)
			}

			atomic.AddInt64((*int64)(&totalQueryDuration), int64(queryDurationPerDay))
			atomic.AddInt64((&totalRuns), int64(runsPerDay))

			if queryDurationPerDay > c.maxQueryDurationPerDay {
				return fmt.Errorf("%q: %s exceeds --max-daily-query-duration=%s (%d runs * %s)", name, queryDurationPerDay.Round(time.Second), c.maxQueryDurationPerDay, runsPerDay, vf.Elapsed.Round(time.Millisecond))
			}

			if len(vf.Rows) > c.MaxResults {
				shortResult := []string{}
				for _, r := range vf.Rows {
					shortResult = append(shortResult, r.String())
				}
				if len(shortResult) >= 10 {
					shortResult = shortResult[0:10]
					shortResult = append(shortResult, "...")
				}

				return fmt.Errorf("%q: %d results exceeds --max-results=%d:\n  %s", name, len(vf.Rows), c.MaxResults, strings.Join(shortResult, "\n  "))
			}

			klog.Infof("%q returned %d rows in %s, daily cost for interval %s (%d runs): %s", name, len(vf.Rows), vf.Elapsed.Round(time.Millisecond), m.Interval, runsPerDay, queryDurationPerDay.Round(time.Second))
			atomic.AddUint64(&verified, 1)
			return nil
		})
	}

	errs := []error{}
	// Someday this might return new go errors
	errs = append(errs, sg.Wait())
	errored := uint64(len(errs))

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
