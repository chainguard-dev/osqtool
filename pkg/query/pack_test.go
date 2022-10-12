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
		Query:       "SELECT * FROM xprotect_reports;",
		Interval:    "1200",
		Description: "Returns a list of malware matches from macOS XProtect",
		Platform:    "darwin",
	}

	if diff := cmp.Diff(got, want, cmpopts.IgnoreUnexported(Metadata{})); diff != "" {
		t.Errorf("Load() got = %v, want %v\n diff: %s", got, want, diff)
	}
}

func TestRender(t *testing.T) {
	m := &Metadata{
		Name:        "xprotect-reports",
		Query:       "SELECT * FROM xprotect_reports;",
		Interval:    "1200",
		Platform:    "darwin",
		Description: "Returns a list of malware matches from macOS XProtect",
	}

	got, err := Render(m)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	want := `-- Returns a list of malware matches from macOS XProtect
--
-- interval: 1200
-- platform: darwin

SELECT * FROM xprotect_reports;
`
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("Load() got = %v, want %v\n diff: %s", got, want, diff)
	}
}
