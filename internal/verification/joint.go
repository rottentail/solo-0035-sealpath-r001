package verification

import (
	"crypto/x509"
	"fmt"
	"sealpath/internal/chain"
	"sealpath/internal/codec"
	"sealpath/internal/jointvalidate"
	"sealpath/internal/model"
	"sealpath/internal/policy"
	"sealpath/internal/revocation"
	"sealpath/internal/signature"
	"sort"
	"time"
)

// jointCandidate is the evaluated state of one submitted artifact signature.
// The distinction between a failed signature, an unknown revocation state and a
// tainted institution is kept explicit: only the last one reaches past the
// combination that would otherwise have used it.
type jointCandidate struct {
	SignatureID   string
	CertificateID string
	Certificate   model.Certificate
	Path          []string
	Revocations   []string
	Checks        []model.Check
	Institution   model.Institution
	Binding       model.RoleBinding
	HasBinding    bool
	Role          string
	Term          int
	Status        string // eligible, provisional, unknown, failed
	FailureScope  string
	ReasonCode    string
	Detail        string
	// Status flags collected before the role binding is resolved.
	Provisional bool
	Unknown     bool
}

func EvaluateJoint(material model.JointMaterial, request model.JointRequest) (model.JointDecision, error) {
	out := model.JointDecision{
		Request:       request,
		TrustRevision: material.TrustSet.Revision,
		Endorsements:  []model.EndorsementOutcome{},
		Institutions:  []model.InstitutionFinding{},
		Combinations:  []model.CombinationOutcome{},
		Checks:        []model.Check{},
		Warnings:      []model.Check{},
		CreatedAt:     time.Now().UTC(),
	}
	if request.At.IsZero() {
		return out, model.Invalid("explicit verification time is required")
	}
	request.At = request.At.UTC()
	out.Request = request
	if request.ArtifactID != material.Artifact.ID || request.TrustSetID != material.TrustSet.ID || request.PolicyID != material.Policy.ID || request.PolicyVersion != material.Policy.Version {
		return out, model.Invalid("request does not match captured evidence")
	}
	if err := jointvalidate.ValidateMaterial(material); err != nil {
		return out, model.Invalid("%v", err)
	}
	if err := jointvalidate.ValidateJointDecision(model.JointDecision{ID: "pending", Request: request, TrustRevision: material.TrustSet.Revision}, material); err != nil {
		return out, model.Invalid("%v", err)
	}
	decoded, err := codec.DecodeCertificates(material.Certificates)
	if err != nil {
		return out, model.Invalid("%v", err)
	}

	byCertificate := map[string][]model.RoleBinding{}
	for _, binding := range material.Bindings {
		byCertificate[binding.CertificateID] = append(byCertificate[binding.CertificateID], binding)
	}
	for id := range byCertificate {
		values := byCertificate[id]
		sort.Slice(values, func(i, j int) bool {
			if values[i].Term != values[j].Term {
				return values[i].Term < values[j].Term
			}
			return values[i].ID < values[j].ID
		})
	}
	institutionCertificates := map[string][]string{}
	for _, binding := range material.Bindings {
		institutionCertificates[binding.InstitutionID] = appendUnique(institutionCertificates[binding.InstitutionID], binding.CertificateID)
	}
	for id := range institutionCertificates {
		sort.Strings(institutionCertificates[id])
	}

	// A compromise is recorded against one certificate but reaches every
	// endorsement by the institution it is bound to, from EffectiveAt onward.
	// The finding does not expire merely because the binding's term later
	// closed; otherwise a renewal or a different combination could hide it.
	compromisedInstitutions := map[string]model.Compromise{}
	for certificateID, compromise := range material.Compromises {
		if compromise.EffectiveAt.After(request.At) {
			continue
		}
		for _, binding := range material.Bindings {
			if binding.CertificateID != certificateID {
				continue
			}
			compromisedInstitutions[binding.InstitutionID] = compromise
		}
	}

	signatureIDs := append([]string(nil), request.SignatureIDs...)
	sort.Strings(signatureIDs)
	candidates := make([]jointCandidate, 0, len(signatureIDs))
	for _, id := range signatureIDs {
		sig, ok := material.Signatures[id]
		if !ok {
			return out, model.Invalid("captured signature %s is absent", id)
		}
		candidate := evaluateJointCandidate(material, request, sig, decoded, byCertificate, compromisedInstitutions)
		candidates = append(candidates, candidate)
		out.Endorsements = append(out.Endorsements, endorsementOutcome(candidate))
	}

	relevant := map[string]bool{}
	for _, candidate := range candidates {
		if candidate.HasBinding {
			relevant[candidate.Institution.ID] = true
		}
	}
	for id := range relevant {
		institution := material.Institutions[id]
		finding := model.InstitutionFinding{InstitutionID: id, Name: institution.Name, Status: institution.Status, Certificates: institutionCertificates[id]}
		if finding.Certificates == nil {
			finding.Certificates = []string{}
		}
		if institution.Status == model.InstitutionSuspended {
			finding.FailureScope = model.ScopeInstitution
			finding.ReasonCode = "institution_suspended"
			finding.Detail = "institution is suspended and its current term cannot endorse"
		}
		if compromise, ok := compromisedInstitutions[id]; ok {
			finding.Status = "compromised"
			finding.FailureScope = model.ScopeInstitution
			finding.ReasonCode = "institution_compromised"
			finding.Detail = fmt.Sprintf("certificate %s exposure recorded effective %s: %s", compromise.CertificateID, compromise.EffectiveAt.UTC().Format(time.RFC3339), compromise.Reason)
		}
		out.Institutions = append(out.Institutions, finding)
	}
	sort.Slice(out.Institutions, func(i, j int) bool { return out.Institutions[i].InstitutionID < out.Institutions[j].InstitutionID })

	combinationIDs := append([]string(nil), request.CombinationIDs...)
	sort.Strings(combinationIDs)
	for _, id := range combinationIDs {
		combination, ok := material.Combinations[id]
		if !ok {
			return out, model.Invalid("captured combination %s is absent", id)
		}
		out.Combinations = append(out.Combinations, evaluateCombination(material, combination, candidates))
	}
	selected := selectCombination(out.Combinations)

	compromised := false
	for _, finding := range out.Institutions {
		if finding.ReasonCode == "institution_compromised" {
			compromised = true
			out.Warnings = append(out.Warnings, model.Check{Code: "institution_integrity", Status: "fail", Detail: fmt.Sprintf("institution %s has recorded certificate exposure effective %s; another certificate or combination cannot restore its standing (%s)", finding.InstitutionID, compromiseTime(material, finding.InstitutionID, compromisedInstitutions), finding.Detail)})
		}
	}
	out.Warnings = append(out.Warnings, model.Check{Code: "disclosure", Status: "pass", Detail: "each combination reports the institutions, certificates, signatures and CRLs it would disclose; selection prefers the smallest sufficient set"})

	switch {
	case compromised:
		out.Verdict = "rejected"
		out.Checks = append(out.Checks, model.Check{Code: "institution_integrity", Status: "fail", Detail: "an institution supplying candidate endorsements has a recorded certificate exposure"})
	case selected >= 0 && out.Combinations[selected].Status == model.EndorsementEligible:
		out.Verdict = "trusted"
		out.SelectedCombination = out.Combinations[selected].CombinationID
		out.Checks = append(out.Checks, model.Check{Code: "endorsement_selection", Status: "pass", Detail: "selected the sufficient combination with the least disclosure"})
	case selected >= 0 && out.Combinations[selected].Status == model.EndorsementProvisional:
		out.Verdict = "trusted_with_warning"
		out.SelectedCombination = out.Combinations[selected].CombinationID
		out.Checks = append(out.Checks, model.Check{Code: "endorsement_selection", Status: "pass", Detail: "selected the sufficient combination with the least disclosure; revocation evidence is best-effort"})
	case anyIndeterminate(out.Combinations):
		out.Verdict = "indeterminate"
		out.Checks = append(out.Checks, model.Check{Code: "endorsement_selection", Status: "unknown", Detail: "no combination is sufficient, but at least one lacks only revocation evidence"})
	default:
		out.Verdict = "rejected"
		out.Checks = append(out.Checks, model.Check{Code: "endorsement_selection", Status: "fail", Detail: "no requested combination is sufficient"})
	}
	if selected >= 0 {
		for _, reason := range out.Combinations[selected].Reasons {
			if reason.Status != "pass" {
				out.Warnings = append(out.Warnings, reason)
			}
		}
	}
	out.Checks = append([]model.Check{{Code: "artifact_identity", Status: "pass", Detail: "artifact identity matches captured content"}}, out.Checks...)
	normalizeJointDecision(&out)
	out.MaterialHash, err = codec.JSONDigest(material)
	if err != nil {
		return out, err
	}
	out.ID, err = codec.JSONDigest(struct {
		Request      model.JointRequest
		MaterialHash string
	}{request, out.MaterialHash})
	return out, err
}

func compromiseTime(material model.JointMaterial, institutionID string, compromised map[string]model.Compromise) string {
	value, ok := compromised[institutionID]
	if !ok {
		return ""
	}
	return value.EffectiveAt.UTC().Format(time.RFC3339)
}

func evaluateJointCandidate(material model.JointMaterial, request model.JointRequest, sig model.Signature, decoded map[string]*x509.Certificate, byCertificate map[string][]model.RoleBinding, compromised map[string]model.Compromise) jointCandidate {
	candidate := jointCandidate{SignatureID: sig.ID, CertificateID: sig.CertificateID, Status: model.EndorsementEligible, Path: []string{}, Revocations: []string{}, Checks: []model.Check{}}
	fail := func(scope, code, detail string) jointCandidate {
		candidate.Status = model.EndorsementFailed
		candidate.FailureScope = scope
		candidate.ReasonCode = code
		candidate.Detail = detail
		candidate.Checks = append(candidate.Checks, model.Check{Code: code, Status: "fail", Detail: detail})
		return candidate
	}
	certificate, ok := material.Certificates[sig.CertificateID]
	if !ok {
		return fail(model.ScopeCandidate, "certificate_absent", "signer certificate is absent")
	}
	parsed, ok := decoded[sig.CertificateID]
	if !ok {
		return fail(model.ScopeCandidate, "certificate_absent", "signer certificate is absent")
	}
	// Derived certificate attributes are never trusted across an evidence
	// boundary; the subject used by policy assessment is re-parsed from DER.
	certificate.Subject = parsed.Subject.String()
	candidate.Certificate = certificate
	if certificate.ID != sig.CertificateID || codec.Digest(certificate.DER) != certificate.ID {
		return fail(model.ScopeCandidate, "certificate_identity", "signer certificate identity is inconsistent")
	}
	for _, check := range policy.Assess(material.Policy, material.Artifact, sig, certificate) {
		candidate.Checks = append(candidate.Checks, check)
		if check.Status == "fail" {
			return fail(model.ScopeCandidate, "policy_"+check.Code, check.Detail)
		}
	}
	if err := signature.Verify(parsed, sig.Algorithm, material.Artifact.Content, sig.Value); err != nil {
		return fail(model.ScopeCandidate, "signature_invalid", err.Error())
	}
	candidate.Checks = append(candidate.Checks, model.Check{Code: "signature", Status: "pass", Detail: "detached signature matches the artifact bytes"})
	path, err := chain.Build(sig.CertificateID, material.Certificates, material.TrustSet, request.At)
	if err != nil {
		return fail(model.ScopeCandidate, "certificate_path", err.Error())
	}
	candidate.Path = path.IDs
	candidate.Checks = append(candidate.Checks, model.Check{Code: "certificate_path", Status: "pass", Detail: fmt.Sprintf("valid code-signing chain with %d certificates", len(path.IDs))})
	unknown := ""
	for i := 0; i+1 < len(path.Certificates); i++ {
		status, id := revocation.Check(path.Certificates[i], path.Certificates[i+1], material.Revocations, request.At)
		status.Code = "revocation:" + path.IDs[i]
		candidate.Checks = append(candidate.Checks, status)
		if id != "" {
			candidate.Revocations = append(candidate.Revocations, id)
		}
		if status.Status == "fail" {
			return fail(model.ScopeCandidate, "revocation", status.Detail)
		}
		if status.Status == "unknown" {
			unknown = status.Detail
		}
	}
	if unknown != "" {
		if material.Policy.Revocation == "best_effort" {
			candidate.Provisional = true
			candidate.ReasonCode = "revocation_unknown"
			candidate.Detail = unknown
			candidate.Checks = append(candidate.Checks, model.Check{Code: "revocation_evidence", Status: "warn", Detail: "best-effort policy permits an explicit warning: " + unknown})
		} else {
			candidate.Unknown = true
			candidate.ReasonCode = "revocation_unknown"
			candidate.Detail = unknown
			candidate.Checks = append(candidate.Checks, model.Check{Code: "revocation_evidence", Status: "unknown", Detail: unknown})
		}
	}

	binding, bindingProblem := bindingAt(material, byCertificate[sig.CertificateID], request.At)
	if bindingProblem != "" {
		scope := model.ScopeCandidate
		if len(byCertificate[sig.CertificateID]) > 0 {
			// The certificate does have receiver role relations; the obstruction
			// is the relation itself, not the absence of any candidate.
			scope = model.ScopeBinding
		}
		return fail(scope, "role_binding_"+bindingProblem, "receiver role binding cannot be used at the requested time: "+bindingProblem)
	}
	candidate.Binding = binding
	candidate.HasBinding = true
	candidate.Role = binding.Role
	candidate.Term = binding.Term
	candidate.Institution = material.Institutions[binding.InstitutionID]
	if compromise, ok := compromised[binding.InstitutionID]; ok {
		candidate.Status = model.EndorsementFailed
		candidate.FailureScope = model.ScopeInstitution
		candidate.ReasonCode = "institution_compromised"
		candidate.Detail = fmt.Sprintf("institution certificate %s exposure recorded effective %s: %s", compromise.CertificateID, compromise.EffectiveAt.UTC().Format(time.RFC3339), compromise.Reason)
		candidate.Checks = append(candidate.Checks, model.Check{Code: "institution_integrity", Status: "fail", Detail: candidate.Detail})
	}
	candidate.recomputeStatus()
	return candidate
}

// recomputeStatus derives the single reported status after the role binding is
// known. A partial endorsement is provisional only for revocation uncertainty;
// if that same certificate also had a definitive failure, the failure wins.
func (c *jointCandidate) recomputeStatus() {
	switch {
	case c.Status == model.EndorsementFailed:
		return
	case c.Unknown:
		c.Status = "unknown"
	case c.Provisional:
		c.Status = model.EndorsementProvisional
	default:
		c.Status = model.EndorsementEligible
	}
}

// bindingAt resolves at most one live binding for a certificate at a time. A
// term closed by suspension stops applying at the suspension instant, so a new
// decision cannot combine that term with a reinstated term.
func bindingAt(material model.JointMaterial, bindings []model.RoleBinding, at time.Time) (model.RoleBinding, string) {
	var chosen model.RoleBinding
	found := false
	closed := false
	for _, binding := range bindings {
		institution, ok := material.Institutions[binding.InstitutionID]
		if !ok || binding.Term < 1 || binding.Term > len(institution.Terms) {
			continue
		}
		term := institution.Terms[binding.Term-1]
		if at.Before(term.StartedAt) || at.Before(binding.NotBefore) || !at.Before(binding.NotAfter) {
			continue
		}
		if term.SuspendedAt != nil && !at.Before(*term.SuspendedAt) {
			closed = true
			continue
		}
		if found {
			// Two live bindings would make the institution identity depend on an
			// arbitrary pick; refuse rather than silently choosing one.
			return model.RoleBinding{}, "ambiguous: multiple live receipts claim this certificate"
		}
		chosen, found = binding, true
	}
	if found {
		return chosen, ""
	}
	if closed {
		return model.RoleBinding{}, "term_closed_by_suspension"
	}
	return model.RoleBinding{}, "absent: no receiver binding covers the requested time"
}

func evaluateCombination(material model.JointMaterial, combination model.EndorsementCombination, candidates []jointCandidate) model.CombinationOutcome {
	out := model.CombinationOutcome{CombinationID: combination.ID, Status: "failed", Assignments: []model.Assignment{}, Disclosure: model.Disclosure{Institutions: []string{}, Certificates: []string{}, Signatures: []string{}, Revocations: []string{}}, Reasons: []model.Check{}}
	if combination.Status != model.CombinationActive {
		out.Reasons = append(out.Reasons, model.Check{Code: "combination", Status: "fail", Detail: "combination is retired and cannot support a new decision"})
		return out
	}
	usable := map[string][]jointCandidate{}
	blocked := map[string][]jointCandidate{}
	for _, candidate := range candidates {
		if !candidate.HasBinding {
			continue
		}
		if candidate.FailureScope == model.ScopeInstitution {
			blocked[candidate.Role] = append(blocked[candidate.Role], candidate)
			continue
		}
		switch candidate.Status {
		case model.EndorsementEligible, model.EndorsementProvisional, "unknown":
			usable[candidate.Role] = append(usable[candidate.Role], candidate)
		case model.EndorsementFailed:
			blocked[candidate.Role] = append(blocked[candidate.Role], candidate)
		}
	}
	sortCandidates(usable)
	sortCandidates(blocked)

	assignment, ok := bestAssignment(combination, usable, func(c jointCandidate) bool { return c.Status == model.EndorsementEligible })
	status := model.EndorsementEligible
	if !ok && material.Policy.Revocation == "best_effort" {
		assignment, ok = bestAssignment(combination, usable, func(c jointCandidate) bool { return c.Status != "unknown" })
		status = model.EndorsementProvisional
	}
	if !ok {
		assignment, ok = bestAssignment(combination, usable, func(c jointCandidate) bool { return true })
		status = "indeterminate"
	}
	if ok {
		out.Status = status
		out.Assignments = assignment
		out.Disclosure = combinationDisclosure(material, candidates, assignment)
		out.Reasons = append(out.Reasons, model.Check{Code: "endorsement_quorum", Status: "pass", Detail: fmt.Sprintf("filled every role slot with %d distinct institutions", len(assignment))})
		if status == model.EndorsementProvisional {
			out.Reasons = append(out.Reasons, model.Check{Code: "revocation_evidence", Status: "warn", Detail: "the assignment relies on best-effort revocation evidence"})
		}
		if status == "indeterminate" {
			out.Reasons = append(out.Reasons, model.Check{Code: "revocation_evidence", Status: "unknown", Detail: "the assignment lacks valid revocation evidence and the policy requires it"})
		}
		return out
	}

	out.Reasons = append(out.Reasons, model.Check{Code: "endorsement_quorum", Status: "fail", Detail: "no distinct institutions can fill every required role"})
	for _, slot := range combination.Slots {
		out.Reasons = append(out.Reasons, model.Check{Code: "slot:" + slot.Role, Status: "fail", Detail: fmt.Sprintf("role %s requires %d distinct institution(s); %d usable, %d blocked", slot.Role, slot.Count, len(usable[slot.Role]), len(blocked[slot.Role]))})
	}
	// List the concrete failures behind "blocked" so the receiver can see
	// whether the obstacle is a single candidate, one role relation, or the
	// whole institution.
	for _, candidate := range sortedCandidates(blocked) {
		scope := candidate.FailureScope
		if scope == "" {
			scope = model.ScopeCandidate
		}
		out.Reasons = append(out.Reasons, model.Check{Code: fmt.Sprintf("blocked:%s:%s", candidate.CertificateID, candidate.ReasonCode), Status: "fail", Detail: fmt.Sprintf("%s failure for certificate %s (role %s, institution %s): %s", scope, candidate.CertificateID, candidate.Role, candidate.Institution.ID, candidate.Detail)})
	}
	sort.Slice(out.Reasons, func(i, j int) bool {
		if out.Reasons[i].Code != out.Reasons[j].Code {
			return out.Reasons[i].Code < out.Reasons[j].Code
		}
		return out.Reasons[i].Detail < out.Reasons[j].Detail
	})
	return out
}

func sortedCandidates(byRole map[string][]jointCandidate) []jointCandidate {
	out := []jointCandidate{}
	for _, values := range byRole {
		out = append(out, values...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CertificateID != out[j].CertificateID {
			return out[i].CertificateID < out[j].CertificateID
		}
		return out[i].SignatureID < out[j].SignatureID
	})
	return out
}

func sortCandidates(values map[string][]jointCandidate) {
	for role := range values {
		sort.Slice(values[role], func(i, j int) bool {
			if values[role][i].Institution.ID != values[role][j].Institution.ID {
				return values[role][i].Institution.ID < values[role][j].Institution.ID
			}
			return values[role][i].SignatureID < values[role][j].SignatureID
		})
	}
}

// bestAssignment fills every slot with a distinct institution. It enumerates
// candidates in deterministic order and keeps the smallest-disclosure
// assignment, so a combination can never count one institution twice.
func bestAssignment(combination model.EndorsementCombination, byRole map[string][]jointCandidate, accept func(jointCandidate) bool) ([]model.Assignment, bool) {
	type slot struct {
		role  string
		count int
	}
	slots := make([]slot, 0)
	for _, value := range combination.Slots {
		slots = append(slots, slot{value.Role, value.Count})
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i].role < slots[j].role })
	expanded := make([]string, 0)
	for _, value := range slots {
		for i := 0; i < value.count; i++ {
			expanded = append(expanded, value.role)
		}
	}
	var current, best []model.Assignment
	used := map[string]bool{}
	var walk func(index int)
	walk = func(index int) {
		if index == len(expanded) {
			if best == nil || assignmentLess(current, best) {
				best = append([]model.Assignment(nil), current...)
			}
			return
		}
		role := expanded[index]
		for _, candidate := range byRole[role] {
			if !accept(candidate) || used[candidate.Institution.ID] {
				continue
			}
			used[candidate.Institution.ID] = true
			current = append(current, model.Assignment{SlotRole: role, InstitutionID: candidate.Institution.ID, SignatureID: candidate.SignatureID, CertificateID: candidate.CertificateID, Term: candidate.Term})
			walk(index + 1)
			current = current[:len(current)-1]
			delete(used, candidate.Institution.ID)
		}
	}
	walk(0)
	return best, best != nil
}

func assignmentLess(left, right []model.Assignment) bool {
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i].InstitutionID != right[i].InstitutionID {
			return left[i].InstitutionID < right[i].InstitutionID
		}
		if left[i].SignatureID != right[i].SignatureID {
			return left[i].SignatureID < right[i].SignatureID
		}
	}
	return len(left) < len(right)
}

func combinationDisclosure(material model.JointMaterial, candidates []jointCandidate, assignments []model.Assignment) model.Disclosure {
	institutions := map[string]bool{}
	certificates := map[string]bool{}
	signatures := map[string]bool{}
	revocations := map[string]bool{}
	for _, assignment := range assignments {
		institutions[assignment.InstitutionID] = true
		signatures[assignment.SignatureID] = true
		for _, candidate := range candidates {
			if candidate.SignatureID != assignment.SignatureID {
				continue
			}
			for _, id := range candidate.Path {
				certificates[id] = true
			}
			for _, id := range candidate.Revocations {
				revocations[id] = true
			}
		}
	}
	out := model.Disclosure{Institutions: sortedKeys(institutions), Certificates: sortedKeys(certificates), Signatures: sortedKeys(signatures), Revocations: sortedKeys(revocations)}
	out.Score = len(out.Institutions) + len(out.Certificates) + len(out.Signatures) + len(out.Revocations)
	return out
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for id := range values {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func selectCombination(outcomes []model.CombinationOutcome) int {
	selected := -1
	for i, outcome := range outcomes {
		if outcome.Status != model.EndorsementEligible && outcome.Status != model.EndorsementProvisional {
			continue
		}
		if selected < 0 {
			selected = i
			continue
		}
		current := outcomes[selected]
		if outcome.Status != current.Status {
			if outcome.Status == model.EndorsementEligible {
				selected = i
			}
			continue
		}
		if outcome.Disclosure.Score != current.Disclosure.Score {
			if outcome.Disclosure.Score < current.Disclosure.Score {
				selected = i
			}
			continue
		}
		if outcome.CombinationID < current.CombinationID {
			selected = i
		}
	}
	return selected
}

func anyIndeterminate(outcomes []model.CombinationOutcome) bool {
	for _, outcome := range outcomes {
		if outcome.Status == "indeterminate" {
			return true
		}
	}
	return false
}

func endorsementOutcome(candidate jointCandidate) model.EndorsementOutcome {
	path := candidate.Path
	if path == nil {
		path = []string{}
	}
	revocations := candidate.Revocations
	if revocations == nil {
		revocations = []string{}
	}
	checks := candidate.Checks
	if checks == nil {
		checks = []model.Check{}
	}
	out := model.EndorsementOutcome{SignatureID: candidate.SignatureID, CertificateID: candidate.CertificateID, Status: candidate.Status, FailureScope: candidate.FailureScope, ReasonCode: candidate.ReasonCode, Detail: candidate.Detail, Path: path, Revocations: revocations, Checks: checks}
	if candidate.HasBinding {
		out.InstitutionID = candidate.Institution.ID
		out.BindingID = candidate.Binding.ID
		out.Role = candidate.Role
		out.Term = candidate.Term
	}
	return out
}

func normalizeJointDecision(decision *model.JointDecision) {
	sort.Slice(decision.Endorsements, func(i, j int) bool {
		return decision.Endorsements[i].SignatureID < decision.Endorsements[j].SignatureID
	})
	sort.Slice(decision.Combinations, func(i, j int) bool {
		return decision.Combinations[i].CombinationID < decision.Combinations[j].CombinationID
	})
	for i := range decision.Combinations {
		if decision.Combinations[i].Assignments == nil {
			decision.Combinations[i].Assignments = []model.Assignment{}
		}
		if decision.Combinations[i].Reasons == nil {
			decision.Combinations[i].Reasons = []model.Check{}
		}
	}
	if decision.Checks == nil {
		decision.Checks = []model.Check{}
	}
	if decision.Warnings == nil {
		decision.Warnings = []model.Check{}
	}
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
