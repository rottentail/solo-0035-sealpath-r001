package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sealpath/internal/artifact"
	"sealpath/internal/authority"
	"sealpath/internal/endorsement"
	"sealpath/internal/evidence"
	"sealpath/internal/model"
	"sealpath/internal/policy"
	"sealpath/internal/signature"
	"time"
)

func walkJoint(c *client, s JointSamples, workflow string) (map[string]any, error) {
	result := map[string]any{"workflow": workflow}
	importCert := func(pem string) error {
		var value model.Certificate
		return c.call("POST", "/v1/certificates", map[string]string{"pem": pem}, &value)
	}
	for _, pem := range []string{s.Root, s.PrimaryCA, s.ReviewerCA, s.PrimaryCert, s.PrimaryRenew, s.ReviewerCert, s.Reviewer2Cert} {
		if err := importCert(pem); err != nil {
			return nil, err
		}
	}
	var trust model.TrustSet
	if err := c.call("POST", "/v1/trust-sets", authority.TrustRequest{ID: "joint-roots", Name: "联合发行根集合", Roots: []string{s.RootID}}, &trust); err != nil {
		return nil, err
	}
	var a model.Artifact
	if err := c.call("POST", "/v1/artifacts", artifact.Request{Name: "joint-release.txt", Content: s.Content}, &a); err != nil {
		return nil, err
	}
	var p model.Policy
	if err := c.call("POST", "/v1/policies", policy.Request{ID: "joint", Algorithms: []string{"ed25519"}, Revocation: "required", MaxArtifactBytes: 1048576}, &p); err != nil {
		return nil, err
	}
	primarySig, err := importSignature(c, a.ID, s.PrimaryID, s.PrimarySig)
	if err != nil {
		return nil, err
	}
	reviewerSig, err := importSignature(c, a.ID, s.ReviewerID, s.ReviewerSig)
	if err != nil {
		return nil, err
	}
	reviewer2Sig, err := importSignature(c, a.ID, s.Reviewer2ID, s.Reviewer2Sig)
	if err != nil {
		return nil, err
	}

	// Receiver-maintained recognition. The institution identity is an explicit
	// record, not a certificate subject string.
	primary, err := putInstitution(c, "alpha", "Alpha发行机构", s.At.AddDate(0, -2, 0))
	if err != nil {
		return nil, err
	}
	reviewer, err := putInstitution(c, "beta", "Beta审核机构", s.At.AddDate(0, -2, 0))
	if err != nil {
		return nil, err
	}
	reviewer2, err := putInstitution(c, "gamma", "Gamma审核机构", s.At.AddDate(0, -2, 0))
	if err != nil {
		return nil, err
	}
	for _, binding := range []endorsement.BindingRequest{
		{ID: "alpha-primary", InstitutionID: primary.ID, CertificateID: s.PrimaryID, Role: model.RolePrimary, NotBefore: s.At.AddDate(0, -1, 0), NotAfter: s.At.AddDate(1, 0, 0)},
		{ID: "beta-reviewer", InstitutionID: reviewer.ID, CertificateID: s.ReviewerID, Role: model.RoleReviewer, NotBefore: s.At.AddDate(0, -1, 0), NotAfter: s.At.AddDate(1, 0, 0)},
		{ID: "gamma-reviewer", InstitutionID: reviewer2.ID, CertificateID: s.Reviewer2ID, Role: model.RoleReviewer, NotBefore: s.At.AddDate(0, -1, 0), NotAfter: s.At.AddDate(1, 0, 0)},
	} {
		var value model.RoleBinding
		if err := c.call("POST", "/v1/role-bindings", binding, &value); err != nil {
			return nil, err
		}
	}
	withReviewer, err := putCombination(c, "primary-plus-reviewer", "主发行方加审核方", []model.RoleSlot{{Role: model.RolePrimary, Count: 1}, {Role: model.RoleReviewer, Count: 1}})
	if err != nil {
		return nil, err
	}
	withTwoReviewers, err := putCombination(c, "two-reviewers", "两家独立审核方", []model.RoleSlot{{Role: model.RoleReviewer, Count: 2}})
	if err != nil {
		return nil, err
	}
	result["institutions"] = []string{primary.ID, reviewer.ID, reviewer2.ID}
	result["combinations"] = []string{withReviewer.ID, withTwoReviewers.ID}
	if workflow == "joint-setup" {
		return result, nil
	}

	// Accept the full revocation corpus: root in the middle, and both issuer
	// CRLs. These are the facts, not the decision.
	for _, pair := range [][2]string{{s.RootID, s.RootCRL}, {s.PrimaryCAID, s.PrimaryCRL}, {s.ReviewerCAID, s.ReviewerCRL}} {
		if err := c.call("POST", "/v1/revocations", map[string]string{"issuer_id": pair[0], "pem": pair[1]}, nil); err != nil {
			return nil, err
		}
	}
	request := model.JointRequest{ArtifactID: a.ID, TrustSetID: trust.ID, PolicyID: p.ID, SignatureIDs: []string{primarySig.ID, reviewerSig.ID, reviewer2Sig.ID}, CombinationIDs: []string{withReviewer.ID, withTwoReviewers.ID}, At: s.At}
	decision, err := jointDecision(c, request)
	if err != nil {
		return nil, err
	}
	result["verdict"] = decision.Verdict
	result["selected"] = decision.SelectedCombination
	result["decision"] = decision.ID
	if workflow == "joint" {
		if decision.Verdict != "trusted" {
			return nil, fmt.Errorf("sufficient combination did not produce a trusted decision: %s", explain(decision))
		}
		best := -1
		for _, outcome := range decision.Combinations {
			if outcome.Status != model.EndorsementEligible && outcome.Status != model.EndorsementProvisional {
				continue
			}
			if best < 0 || outcome.Disclosure.Score < best {
				best = outcome.Disclosure.Score
			}
		}
		for _, outcome := range decision.Combinations {
			if outcome.CombinationID == decision.SelectedCombination && outcome.Disclosure.Score != best {
				return nil, fmt.Errorf("selected a sufficient combination with avoidable disclosure")
			}
		}
		scores := map[string]int{}
		for _, outcome := range decision.Combinations {
			scores[outcome.CombinationID] = outcome.Disclosure.Score
		}
		result["disclosure_scores"] = scores
		return result, nil
	}

	switch workflow {
	case "joint-hidden-compromise":
		// The original primary certificate is explicitly reported exposed. A
		// different combination still verifies, but the institution-wide failure
		// must not be laundered into a trusted verdict.
		if _, err := recordCompromise(c, s.PrimaryID, s.At.Add(-time.Hour), "primary signing key published on a paste site"); err != nil {
			return nil, err
		}
		after, err := jointDecision(c, request)
		if err != nil {
			return nil, err
		}
		if after.Verdict != "rejected" {
			return nil, fmt.Errorf("institution exposure was hidden by choosing another combination")
		}
		found := false
		for _, finding := range after.Institutions {
			if finding.ReasonCode == "institution_compromised" {
				found = true
				result["compromised_institution"] = finding.InstitutionID
				result["compromise_scope"] = finding.FailureScope
			}
		}
		if !found {
			return nil, fmt.Errorf("institution-level finding was not reported")
		}
		result["verdict"] = after.Verdict
		result["decision"] = after.ID
		return result, nil

	case "joint-renewal":
		// A renewed certificate from the same institution must not be counted as
		// a second institution. Binding it as a second primary in the same term
		// is refused; the original combination still fills one primary slot.
		var rejected bool
		err := c.call("POST", "/v1/role-bindings", endorsement.BindingRequest{ID: "alpha-primary-renewed", InstitutionID: primary.ID, CertificateID: s.PrimaryRenewID, Role: model.RolePrimary, NotBefore: s.At.AddDate(0, -1, 0), NotAfter: s.At.AddDate(1, 0, 0), Term: 1}, nil)
		if err == nil {
			return nil, fmt.Errorf("a renewed certificate was allowed to duplicate the primary vote")
		}
		result["renewal_error"] = err.Error()
		rejected = true
		result["renewal_binding_refused"] = rejected
		return result, nil

	case "joint-suspension":
		// Suspend beta after the original decision, then reinstate it. The old
		// decision must still explain which institution endorsed it; a new
		// decision must not silently reuse the closed term's binding.
		if err := c.call("POST", "/v1/institutions/"+reviewer.ID+"/suspend", map[string]any{"expected_revision": reviewer.Revision, "at": s.At.Add(30 * time.Minute)}, &reviewer); err != nil {
			return nil, err
		}
		historical, err := c.callGet("/v1/joint-decisions/" + decision.ID)
		if err != nil {
			return nil, err
		}
		var old model.JointDecision
		if err := json.Unmarshal(historical, &old); err != nil {
			return nil, err
		}
		if old.Verdict != "trusted" {
			return nil, fmt.Errorf("suspension rewrote an already completed decision")
		}
		// While suspended, the closed term cannot supply a new endorsement.
		suspendedRequest := request
		suspendedRequest.At = s.At.Add(45 * time.Minute)
		// Only the two-reviewer combination is requested, so losing beta's
		// endorsement cannot be papered over by the primary-plus-reviewer shape.
		suspendedRequest.CombinationIDs = []string{withTwoReviewers.ID}
		suspended, err := jointDecision(c, suspendedRequest)
		if err != nil {
			return nil, err
		}
		if suspended.Verdict == "trusted" || suspended.Verdict == "trusted_with_warning" {
			return nil, fmt.Errorf("a suspended institution still endorsed a new decision")
		}
		if err := c.call("POST", "/v1/institutions/"+reviewer.ID+"/reinstate", map[string]any{"expected_revision": reviewer.Revision, "at": s.At.Add(60 * time.Minute)}, &reviewer); err != nil {
			return nil, err
		}
		// Reinstatement opens term 2. The old term-1 binding must not authorize
		// the new term; a fresh binding for term 2 must be registered explicitly.
		if reviewer.CurrentTerm != 2 {
			return nil, fmt.Errorf("reinstatement did not open a new term")
		}
		var wrongTerm bool
		if err := c.call("POST", "/v1/role-bindings", endorsement.BindingRequest{ID: "beta-reviewer-reused", InstitutionID: reviewer.ID, CertificateID: s.ReviewerID, Role: model.RoleReviewer, Term: 1, NotBefore: s.At.AddDate(0, -1, 0), NotAfter: s.At.AddDate(1, 0, 0)}, nil); err == nil {
			wrongTerm = true
		}
		if wrongTerm {
			return nil, fmt.Errorf("a term-1 binding was accepted for a later term without review")
		}
		result["historical_verdict"] = old.Verdict
		result["historical_institution"] = old.Endorsements[0].InstitutionID
		result["suspended_verdict"] = suspended.Verdict
		result["suspended_combination_status"] = suspended.Combinations[0].Status
		result["reviewer_term"] = reviewer.CurrentTerm
		return result, nil

	case "joint-bundle":
		var bundle model.JointBundle
		if err := c.call("GET", "/v1/joint-decisions/"+decision.ID+"/bundle", nil, &bundle); err != nil {
			return nil, err
		}
		var replay evidence.JointReplayResult
		if err := c.call("POST", "/v1/joint-evidence/replay", bundle, &replay); err != nil {
			return nil, err
		}
		if !replay.Matches || replay.DecisionID != decision.ID {
			return nil, fmt.Errorf("joint evidence did not replay")
		}
		result["replay"] = replay
		return result, nil

	case "joint-compare":
		if _, err := recordCompromise(c, s.Reviewer2ID, s.At.Add(-time.Hour), "reviewer key suspected exposed"); err != nil {
			return nil, err
		}
		after, err := jointDecision(c, request)
		if err != nil {
			return nil, err
		}
		var comparison evidence.JointComparison
		if err := c.call("GET", "/v1/joint-evidence/compare?left="+decision.ID+"&right="+after.ID, nil, &comparison); err != nil {
			return nil, err
		}
		result["left_verdict"] = decision.Verdict
		result["right_verdict"] = after.Verdict
		result["differences"] = len(comparison.Differences)
		return result, nil
	}
	return nil, fmt.Errorf("unknown joint workflow %s", workflow)
}

func explain(decision model.JointDecision) string {
	return fmt.Sprintf("verdict=%s checks=%v combinations=%v", decision.Verdict, decision.Checks, decision.Combinations)
}

func importSignature(c *client, artifactID, certificateID string, value []byte) (model.Signature, error) {
	var out model.Signature
	err := c.call("POST", "/v1/signatures", signature.Request{ArtifactID: artifactID, CertificateID: certificateID, Algorithm: "ed25519", Value: value}, &out)
	return out, err
}

func putInstitution(c *client, id, name string, startedAt time.Time) (model.Institution, error) {
	var out model.Institution
	err := c.call("POST", "/v1/institutions", endorsement.InstitutionRequest{ID: id, Name: name, StartedAt: startedAt}, &out)
	return out, err
}

func putCombination(c *client, id, name string, slots []model.RoleSlot) (model.EndorsementCombination, error) {
	var out model.EndorsementCombination
	err := c.call("POST", "/v1/endorsement-combinations", endorsement.CombinationRequest{ID: id, Name: name, Slots: slots}, &out)
	return out, err
}

func recordCompromise(c *client, certificateID string, at time.Time, reason string) (model.Compromise, error) {
	var out model.Compromise
	err := c.call("POST", "/v1/compromises", endorsement.CompromiseRequest{CertificateID: certificateID, EffectiveAt: at, Reason: reason}, &out)
	return out, err
}

func jointDecision(c *client, request model.JointRequest) (model.JointDecision, error) {
	var out model.JointDecision
	err := c.call("POST", "/v1/joint-decisions", request, &out)
	return out, err
}

func (c *client) callGet(path string) ([]byte, error) {
	request, err := http.NewRequest("GET", c.base+path, nil)
	if err != nil {
		return nil, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s returned %d: %s", path, response.StatusCode, data)
	}
	return data, nil
}
