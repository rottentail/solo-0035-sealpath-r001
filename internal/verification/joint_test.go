package verification

import (
	"testing"
	"time"

	"sealpath/internal/model"
)

func TestSelectCombinationPrefersLeastDisclosure(t *testing.T) {
	outcomes := []model.CombinationOutcome{
		{CombinationID: "large", Status: model.EndorsementEligible, Disclosure: model.Disclosure{Score: 12}},
		{CombinationID: "small", Status: model.EndorsementEligible, Disclosure: model.Disclosure{Score: 10}},
		{CombinationID: "indeterminate", Status: "indeterminate", Disclosure: model.Disclosure{Score: 1}},
	}
	if got := selectCombination(outcomes); got != 1 {
		t.Fatalf("expected smallest sufficient combination, got index %d", got)
	}
}

func TestBestAssignmentRefusesDuplicateInstitution(t *testing.T) {
	combination := model.EndorsementCombination{ID: "two-reviewers", Slots: []model.RoleSlot{{Role: model.RoleReviewer, Count: 2}}}
	byRole := map[string][]jointCandidate{
		model.RoleReviewer: {
			{SignatureID: "sig-a", Institution: model.Institution{ID: "alpha"}},
			{SignatureID: "sig-b", Institution: model.Institution{ID: "alpha"}},
		},
	}
	if assignment, ok := bestAssignment(combination, byRole, func(jointCandidate) bool { return true }); ok {
		t.Fatalf("one institution filled two reviewer slots: %v", assignment)
	}
}

func TestBestAssignmentRequiresDistinctInstitutions(t *testing.T) {
	combination := model.EndorsementCombination{ID: "mixed", Slots: []model.RoleSlot{{Role: model.RolePrimary, Count: 1}, {Role: model.RoleReviewer, Count: 1}}}
	byRole := map[string][]jointCandidate{
		model.RolePrimary:  {{SignatureID: "sig-a", Institution: model.Institution{ID: "alpha"}}},
		model.RoleReviewer: {{SignatureID: "sig-b", Institution: model.Institution{ID: "beta"}}},
	}
	assignment, ok := bestAssignment(combination, byRole, func(jointCandidate) bool { return true })
	if !ok || len(assignment) != 2 {
		t.Fatalf("expected a two-institution assignment, got %v", assignment)
	}
	if assignment[0].InstitutionID == assignment[1].InstitutionID {
		t.Fatalf("assignment reused an institution")
	}
}

func TestBindingAtStopsAtSuspension(t *testing.T) {
	suspended := time.Date(2026, 11, 16, 1, 0, 0, 0, time.UTC)
	institution := model.Institution{ID: "a", Status: model.InstitutionSuspended, CurrentTerm: 1, Terms: []model.InstitutionTerm{{Term: 1, StartedAt: suspended.Add(-time.Hour), SuspendedAt: &suspended}}}
	material := model.JointMaterial{Institutions: map[string]model.Institution{"a": institution}}
	bindings := []model.RoleBinding{{ID: "b", InstitutionID: "a", CertificateID: "c", Role: model.RolePrimary, Term: 1, NotBefore: suspended.Add(-time.Hour), NotAfter: suspended.Add(time.Hour)}}
	if _, problem := bindingAt(material, bindings, suspended.Add(-time.Minute)); problem != "" {
		t.Fatalf("binding before suspension must still apply: %s", problem)
	}
	if _, problem := bindingAt(material, bindings, suspended.Add(time.Minute)); problem != "term_closed_by_suspension" {
		t.Fatalf("binding from a closed term must report the closed term, got %q", problem)
	}
}

func TestBindingAtRefusesAmbiguity(t *testing.T) {
	start := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	institution := model.Institution{ID: "a", Status: model.InstitutionActive, CurrentTerm: 1, Terms: []model.InstitutionTerm{{Term: 1, StartedAt: start.Add(-time.Hour)}}}
	material := model.JointMaterial{Institutions: map[string]model.Institution{"a": institution}}
	bindings := []model.RoleBinding{
		{ID: "b1", InstitutionID: "a", CertificateID: "c", Role: model.RolePrimary, Term: 1, NotBefore: start.Add(-time.Hour), NotAfter: start.Add(time.Hour)},
		{ID: "b2", InstitutionID: "a", CertificateID: "c", Role: model.RoleReviewer, Term: 1, NotBefore: start.Add(-time.Hour), NotAfter: start.Add(time.Hour)},
	}
	if _, problem := bindingAt(material, bindings, start); problem == "" {
		t.Fatalf("ambiguous live bindings must not silently resolve")
	}
}

func TestEvaluateJointRejectsMismatchedRequest(t *testing.T) {
	material := model.JointMaterial{
		Artifact:     model.Artifact{ID: "artifact", Content: []byte("x"), Size: 1},
		TrustSet:     model.TrustSet{ID: "trust", Status: "active", Roots: []string{"root"}, Revision: 1},
		Policy:       model.Policy{ID: "policy", Version: 1, Status: "active"},
		Signatures:   map[string]model.Signature{},
		Certificates: map[string]model.Certificate{"root": {ID: "root"}},
		Revocations:  map[string]model.RevocationList{},
		Institutions: map[string]model.Institution{},
		Bindings:     map[string]model.RoleBinding{},
		Combinations: map[string]model.EndorsementCombination{},
		Compromises:  map[string]model.Compromise{},
	}
	request := model.JointRequest{ArtifactID: "other", TrustSetID: "trust", PolicyID: "policy", PolicyVersion: 1, At: time.Now().UTC()}
	if _, err := EvaluateJoint(material, request); err == nil {
		t.Fatalf("a request naming another artifact must be rejected")
	}
}
