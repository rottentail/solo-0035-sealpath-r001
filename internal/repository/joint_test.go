package repository

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sealpath/internal/model"
)

func TestOpenRejectsJointStateWithoutMaterial(t *testing.T) {
	state := model.NewState()
	state.JointDecisions["d"] = model.JointDecision{ID: "d", Verdict: "trusted"}
	path := filepath.Join(t.TempDir(), "state.json")
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatalf("state with a joint decision but no captured material must be rejected")
	}
}

func TestOpenRejectsInvalidInstitution(t *testing.T) {
	state := model.NewState()
	state.Institutions["a"] = model.Institution{ID: "a", Name: "A", Status: "unknown", CurrentTerm: 1, Revision: 1, Terms: []model.InstitutionTerm{{Term: 1, StartedAt: time.Now().UTC()}}}
	path := filepath.Join(t.TempDir(), "state.json")
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatalf("state with an unknown institution status must be rejected")
	}
}
