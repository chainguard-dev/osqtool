package query

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestLoad(t *testing.T) {
	got, err := Load("testdata/xprotect-reports.sql")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	want := &Metadata{
		Name:        "xprotect-reports",
		Query:       "SELECT\n  *\nFROM\n  xprotect_reports;",
		Interval:    1200,
		Description: "Returns a list of malware matches from macOS XProtect",
	}

	if diff := cmp.Diff(got, want, cmpopts.IgnoreUnexported(Metadata{})); diff != "" {
		t.Errorf("Load() got = %v, want %v\n diff: %s", got, want, diff)
	}
}
