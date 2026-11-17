package evidence

import (
	"reflect"
	"sealpath/internal/codec"
	"sealpath/internal/model"
	"sealpath/internal/verification"
)

func (s Service) ExportJoint(id string) (model.JointBundle, error) {
	st, err := s.Store.Snapshot()
	if err != nil {
		return model.JointBundle{}, err
	}
	decision, ok := st.JointDecisions[id]
	if !ok {
		return model.JointBundle{}, model.Missing("joint decision", id)
	}
	bundle := model.JointBundle{Format: "sealpath-joint-evidence-v1", Decision: decision, Material: st.JointMaterials[id]}
	bundle.Digest, err = jointBundleDigest(bundle)
	return bundle, err
}

func jointBundleDigest(bundle model.JointBundle) (string, error) {
	bundle.Digest = ""
	return codec.JSONDigest(bundle)
}

type JointReplayResult struct {
	Matches      bool   `json:"matches"`
	Verdict      string `json:"verdict"`
	DecisionID   string `json:"decision_id"`
	Authenticity string `json:"authenticity"`
}

func ReplayJoint(bundle model.JointBundle) (JointReplayResult, error) {
	var out JointReplayResult
	if bundle.Format != "sealpath-joint-evidence-v1" {
		return out, model.Invalid("unsupported joint evidence format")
	}
	hash, err := jointBundleDigest(bundle)
	if err != nil {
		return out, err
	}
	if hash != bundle.Digest {
		return out, model.Invalid("joint bundle digest mismatch")
	}
	result, err := verification.EvaluateJoint(bundle.Material, bundle.Decision.Request)
	if err != nil {
		return out, err
	}
	original := bundle.Decision
	if result.ID != original.ID ||
		result.MaterialHash != original.MaterialHash ||
		result.Verdict != original.Verdict ||
		result.TrustRevision != original.TrustRevision ||
		result.SelectedCombination != original.SelectedCombination ||
		!reflect.DeepEqual(result.Endorsements, original.Endorsements) ||
		!reflect.DeepEqual(result.Institutions, original.Institutions) ||
		!reflect.DeepEqual(result.Combinations, original.Combinations) ||
		!reflect.DeepEqual(result.Checks, original.Checks) ||
		!reflect.DeepEqual(result.Warnings, original.Warnings) {
		return out, model.Invalid("joint decision cannot be reproduced from captured evidence")
	}
	out = JointReplayResult{Matches: true, Verdict: result.Verdict, DecisionID: result.ID, Authenticity: "self-contained consistency; institutional recognition must be established separately"}
	return out, nil
}

type JointDifference struct {
	Field  string `json:"field"`
	Before any    `json:"before"`
	After  any    `json:"after"`
}

type JointComparison struct {
	Left         string            `json:"left"`
	Right        string            `json:"right"`
	SameArtifact bool              `json:"same_artifact"`
	Differences  []JointDifference `json:"differences"`
}

func (s Service) CompareJoint(left, right string) (JointComparison, error) {
	st, err := s.Store.Snapshot()
	if err != nil {
		return JointComparison{}, err
	}
	a, ok := st.JointDecisions[left]
	if !ok {
		return JointComparison{}, model.Missing("joint decision", left)
	}
	b, ok := st.JointDecisions[right]
	if !ok {
		return JointComparison{}, model.Missing("joint decision", right)
	}
	ma, mb := st.JointMaterials[left], st.JointMaterials[right]
	out := JointComparison{Left: left, Right: right, SameArtifact: ma.Artifact.ID == mb.Artifact.ID, Differences: []JointDifference{}}
	add := func(field string, x, y any) {
		if !reflect.DeepEqual(x, y) {
			out.Differences = append(out.Differences, JointDifference{field, x, y})
		}
	}
	add("artifact", ma.Artifact.ID, mb.Artifact.ID)
	add("verdict", a.Verdict, b.Verdict)
	add("time", a.Request.At, b.Request.At)
	add("policy", ma.Policy, mb.Policy)
	add("trust_roots", ma.TrustSet.Roots, mb.TrustSet.Roots)
	add("selected_combination", a.SelectedCombination, b.SelectedCombination)
	add("endorsements", a.Endorsements, b.Endorsements)
	add("institutions", a.Institutions, b.Institutions)
	add("combinations", a.Combinations, b.Combinations)
	add("warnings", a.Warnings, b.Warnings)
	return out, nil
}
