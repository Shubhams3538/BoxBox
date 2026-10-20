package service

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"testing"
)

// referenceSortEntries remains a simple ordering oracle for sortEntries.
func referenceSortEntries(entries []fs.FileInfo, sortBy, sortDir string) {
	sort.Slice(entries, func(i, j int) bool {
		left := entries[i]
		right := entries[j]
		leftName := left.Name()
		rightName := right.Name()
		leftHidden := strings.HasPrefix(leftName, ".")
		rightHidden := strings.HasPrefix(rightName, ".")

		if leftHidden != rightHidden {
			return !leftHidden
		}

		comparison := 0
		switch sortBy {
		case "name":
			comparison = strings.Compare(strings.ToLower(leftName), strings.ToLower(rightName))
		case "size":
			comparison = compareInt64(left.Size(), right.Size())
		case "modTime":
			comparison = left.ModTime().Compare(right.ModTime())
		case "type":
			if left.IsDir() != right.IsDir() {
				return left.IsDir()
			}
			comparison = strings.Compare(strings.ToLower(leftName), strings.ToLower(rightName))
		default:
			comparison = strings.Compare(strings.ToLower(leftName), strings.ToLower(rightName))
		}
		if comparison == 0 {
			comparison = strings.Compare(strings.ToLower(leftName), strings.ToLower(rightName))
		}

		if sortDir == "desc" {
			return comparison > 0
		}
		return comparison < 0
	})
}

func TestSortEntriesKeepsTheReferenceOrder(t *testing.T) {
	svc, fsys := setupTestFileService()
	dir := "/data/media/sorting"
	if err := fsys.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	names := []string{"b.txt", "B.txt", "a.TXT", ".hidden", ".Alpha", "Zed", "zed.md", "10.txt", "9.txt", "éclair.txt", "Éclair2.txt"}
	for i, name := range names {
		if err := fsys.WriteFile(fmt.Sprintf("%s/%s", dir, name), []byte(strings.Repeat("x", i%4)), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, folder := range []string{"Folder", "apps", ".config"} {
		if err := fsys.MkdirAll(dir+"/"+folder, 0755); err != nil {
			t.Fatal(err)
		}
	}
	entries, _, err := fsys.ReadDirFileInfoLimit(dir, 0)
	if err != nil {
		t.Fatal(err)
	}

	for _, sortBy := range []string{"name", "type", "size", "modTime", ""} {
		for _, sortDir := range []string{"asc", "desc"} {
			want := append([]fs.FileInfo(nil), entries...)
			got := append([]fs.FileInfo(nil), entries...)
			referenceSortEntries(want, sortBy, sortDir)
			svc.(*fileService).sortEntries(got, sortBy, sortDir)
			for i := range want {
				if want[i].Name() != got[i].Name() {
					t.Fatalf("sort=%q dir=%s: position %d is %q, reference has %q", sortBy, sortDir, i, got[i].Name(), want[i].Name())
				}
			}
		}
	}
}
