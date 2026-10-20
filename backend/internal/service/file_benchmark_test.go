package service

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jR4dh3y/BoxBox/backend/internal/model"
	"github.com/jR4dh3y/BoxBox/backend/internal/pkg/filesystem"
)

func BenchmarkDirectoryListing(b *testing.B) {
	for _, count := range []int{1_000, 10_000} {
		b.Run(fmt.Sprintf("%d_entries", count), func(b *testing.B) {
			fs := filesystem.NewOsFS()
			dir := b.TempDir()
			svc := NewFileService(fs, FileServiceConfig{MountPoints: []model.MountPoint{{Name: "benchmark", Path: dir}}})
			names := make([]string, count)
			for i := count - 1; i >= 0; i-- {
				prefix := "Project"
				if i%2 != 0 {
					prefix = "project"
				}
				names[i] = fmt.Sprintf("%s File %05d.MKV", prefix, i)
				if err := fs.WriteFile(filepath.Join(dir, names[i]), nil, 0644); err != nil {
					b.Fatal(err)
				}
			}
			sort.Slice(names, func(i, j int) bool {
				return strings.ToLower(names[i]) < strings.ToLower(names[j])
			})

			ctx := context.Background()
			opts := model.ListOptions{SortBy: "name", SortDir: "asc"}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				list, err := svc.List(ctx, "benchmark", opts)
				if err != nil {
					b.Fatal(err)
				}
				if list.Path != "benchmark" || len(list.Items) != count {
					b.Fatalf("unexpected listing: path %q, %d items; want benchmark and %d", list.Path, len(list.Items), count)
				}
				for i, item := range list.Items {
					if want := names[i]; item.Name != want {
						b.Fatalf("unexpected item %d: got %q, want %q", i, item.Name, want)
					}
				}
			}
		})
	}
}
