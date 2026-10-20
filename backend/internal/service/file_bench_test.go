package service

import (
	"context"
	"fmt"
	"mime"
	"reflect"
	"testing"

	"github.com/jR4dh3y/BoxBox/backend/internal/model"
)

const benchDirectoryEntries = 5000

func setupBenchDirectory(tb testing.TB, entries int) FileService {
	tb.Helper()
	svc, fs := setupTestFileService()
	dir := "/data/media/bench"
	if err := fs.MkdirAll(dir, 0755); err != nil {
		tb.Fatal(err)
	}
	for i := range entries {
		name := fmt.Sprintf("%s/File-%05d.TXT", dir, (i*7919)%entries)
		if err := fs.WriteFile(name, []byte("x"), 0644); err != nil {
			tb.Fatal(err)
		}
	}
	return svc
}

// fullListingBenchOptions keeps archived pagination baselines on the same full-list workload.
func fullListingBenchOptions(sortBy string, entries int) model.ListOptions {
	opts := model.ListOptions{SortBy: sortBy, SortDir: "asc"}
	pageSize := reflect.ValueOf(&opts).Elem().FieldByName("PageSize")
	if pageSize.IsValid() && pageSize.CanSet() && pageSize.Kind() == reflect.Int {
		pageSize.SetInt(int64(entries))
	}
	return opts
}

func BenchmarkListDirectory(b *testing.B) {
	svc := setupBenchDirectory(b, benchDirectoryEntries)
	ctx := context.Background()
	// MIME tables initialize once per process, not once per directory listing.
	mime.TypeByExtension(".TXT")
	for _, sortBy := range []string{"name", "type", "size", "modTime"} {
		b.Run(sortBy, func(b *testing.B) {
			opts := fullListingBenchOptions(sortBy, benchDirectoryEntries)
			b.ReportAllocs()
			for b.Loop() {
				list, err := svc.List(ctx, "media/bench", opts)
				if err != nil {
					b.Fatal(err)
				}
				if len(list.Items) != benchDirectoryEntries {
					b.Fatalf("got %d items, want %d", len(list.Items), benchDirectoryEntries)
				}
			}
		})
	}
}

// Allocation counts are deterministic, unlike wall-clock time, so they can gate CI.
// Lower the ceiling when an optimisation lands; never raise it to make a change pass.
func TestListDirectoryAllocationCeiling(t *testing.T) {
	const entries = 1000
	svc := setupBenchDirectory(t, entries)
	ctx := context.Background()
	for _, sortBy := range []string{"name", "type", "size", "modTime"} {
		ceiling := allocationCeiling(t, "list/"+sortBy)
		opts := fullListingBenchOptions(sortBy, entries)
		allocs := testing.AllocsPerRun(5, func() {
			list, err := svc.List(ctx, "media/bench", opts)
			if err != nil {
				t.Fatal(err)
			}
			if len(list.Items) != entries {
				t.Fatalf("got %d items, want %d", len(list.Items), entries)
			}
		})
		t.Logf("sort=%s allocs=%.0f ceiling=%.0f", sortBy, allocs, ceiling)
		if allocs > ceiling {
			t.Errorf("sort=%s: %.0f allocs per List of %d entries exceeds ceiling %.0f", sortBy, allocs, entries, ceiling)
		}
	}
}
