package endorsement

import (
	"testing"
	"time"

	"sealpath/internal/jointvalidate"
	"sealpath/internal/model"
)

func TestIntervalsOverlap(t *testing.T) {
	start := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	a := model.RoleBinding{NotBefore: start, NotAfter: start.Add(time.Hour)}
	b := model.RoleBinding{NotBefore: start.Add(30 * time.Minute), NotAfter: start.Add(2 * time.Hour)}
	if !intervalsOverlap(a, b) {
		t.Fatalf("expected overlap")
	}
	c := model.RoleBinding{NotBefore: start.Add(time.Hour), NotAfter: start.Add(2 * time.Hour)}
	if intervalsOverlap(a, c) {
		t.Fatalf("touching intervals must not overlap")
	}
}

func TestValidateCombinationShapes(t *testing.T) {
	cases := []struct {
		name  string
		slots []model.RoleSlot
		ok    bool
	}{
		{"primary reviewer", []model.RoleSlot{{Role: model.RolePrimary, Count: 1}, {Role: model.RoleReviewer, Count: 1}}, true},
		{"two reviewers", []model.RoleSlot{{Role: model.RoleReviewer, Count: 2}}, true},
		{"single reviewer", []model.RoleSlot{{Role: model.RoleReviewer, Count: 1}}, false},
		{"two primaries", []model.RoleSlot{{Role: model.RolePrimary, Count: 2}}, false},
		{"three reviewers", []model.RoleSlot{{Role: model.RoleReviewer, Count: 3}}, false},
		{"primary three reviewers", []model.RoleSlot{{Role: model.RolePrimary, Count: 1}, {Role: model.RoleReviewer, Count: 3}}, false},
	}
	for _, tc := range cases {
		value := model.EndorsementCombination{ID: "c", Name: "c", Status: model.CombinationActive, Revision: 1, Slots: tc.slots}
		if err := jointvalidate.ValidateCombination(value); (err == nil) != tc.ok {
			t.Fatalf("%s: expected ok=%v, got %v", tc.name, tc.ok, err)
		}
	}
}
