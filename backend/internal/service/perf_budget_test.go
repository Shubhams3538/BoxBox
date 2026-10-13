package service

import (
	_ "embed"
	"encoding/json"
	"testing"
)

//go:embed perf-budget.json
var performanceBudget []byte

func allocationCeiling(t testing.TB, name string) float64 {
	t.Helper()
	var ceilings map[string]float64
	if err := json.Unmarshal(performanceBudget, &ceilings); err != nil {
		t.Fatal(err)
	}
	ceiling, ok := ceilings[name]
	if !ok || ceiling <= 0 {
		t.Fatalf("missing or invalid performance ceiling %q", name)
	}
	return ceiling
}
