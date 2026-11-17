package jointvalidate

import (
	"crypto/x509"
	"fmt"
	"sealpath/internal/codec"
	"sealpath/internal/model"
)

// ValidateMaterial checks the structural and content identities that a joint
// decision or evidence bundle relies on. It does not perform certificate path
// or signature verification; those remain part of evaluation.
func ValidateMaterial(m model.JointMaterial) error {
	if m.Signatures == nil || m.Certificates == nil || m.Revocations == nil || m.Institutions == nil || m.Bindings == nil || m.Combinations == nil || m.Compromises == nil {
		return fmt.Errorf("joint material collections must not be null")
	}
	if codec.Digest(m.Artifact.Content) != m.Artifact.ID || m.Artifact.Size != len(m.Artifact.Content) {
		return fmt.Errorf("joint artifact identity is inconsistent")
	}
	if m.TrustSet.ID == "" || m.TrustSet.Status != "active" || len(m.TrustSet.Roots) == 0 {
		return fmt.Errorf("joint trust set is not active")
	}
	for _, root := range m.TrustSet.Roots {
		if _, ok := m.Certificates[root]; !ok {
			return fmt.Errorf("joint trust root %s is absent", root)
		}
	}
	if m.Policy.ID == "" || m.Policy.Version < 1 || m.Policy.Status != "active" {
		return fmt.Errorf("joint policy is not usable")
	}
	decoded, err := codec.DecodeCertificates(m.Certificates)
	if err != nil {
		return err
	}
	if err := codec.ValidateRevocations(m.Revocations, m.Certificates); err != nil {
		return err
	}
	for id, cert := range m.Certificates {
		if cert.ID != id {
			return fmt.Errorf("joint certificate identity mismatch %s", id)
		}
	}
	for id, sig := range m.Signatures {
		if sig.ID != id {
			return fmt.Errorf("joint signature identity mismatch %s", id)
		}
		if sig.ArtifactID != m.Artifact.ID {
			return fmt.Errorf("joint signature %s is bound to another artifact", id)
		}
		if _, ok := m.Certificates[sig.CertificateID]; !ok {
			return fmt.Errorf("joint signature %s references a missing certificate", id)
		}
		if expected, err := signatureIdentity(sig); err != nil || expected != id {
			return fmt.Errorf("joint signature %s does not match its material", id)
		}
	}
	for id, value := range m.Institutions {
		if err := ValidateInstitution(value); err != nil || value.ID != id {
			return fmt.Errorf("joint institution %s is inconsistent: %v", id, err)
		}
	}
	for id, binding := range m.Bindings {
		if err := ValidateBinding(binding, m.Institutions, m.Certificates, decoded); err != nil {
			return fmt.Errorf("joint role binding %s is inconsistent: %v", id, err)
		}
		if binding.ID != id {
			return fmt.Errorf("joint role binding identity mismatch %s", id)
		}
	}
	if err := validateCurrentTermBindings(m.Bindings); err != nil {
		return err
	}
	for id, combination := range m.Combinations {
		if err := ValidateCombination(combination); err != nil {
			return fmt.Errorf("joint combination %s is inconsistent: %v", id, err)
		}
		if combination.ID != id {
			return fmt.Errorf("joint combination identity mismatch %s", id)
		}
	}
	for id, compromise := range m.Compromises {
		if compromise.CertificateID != id {
			return fmt.Errorf("joint compromise identity mismatch %s", id)
		}
		if _, ok := m.Certificates[compromise.CertificateID]; !ok {
			return fmt.Errorf("joint compromise references a missing certificate %s", id)
		}
		if compromise.EffectiveAt.IsZero() || compromise.Reason == "" {
			return fmt.Errorf("joint compromise %s lacks an effective time or reason", id)
		}
	}
	return nil
}

func signatureIdentity(sig model.Signature) (string, error) {
	return codec.JSONDigest(struct {
		ArtifactID    string `json:"artifact_id"`
		CertificateID string `json:"certificate_id"`
		Algorithm     string `json:"algorithm"`
		Value         []byte `json:"value"`
	}{sig.ArtifactID, sig.CertificateID, sig.Algorithm, sig.Value})
}

func ValidateInstitution(value model.Institution) error {
	if value.ID == "" || value.Name == "" || len(value.Name) > 200 {
		return fmt.Errorf("institution needs an id and a name")
	}
	if value.Status != model.InstitutionActive && value.Status != model.InstitutionSuspended {
		return fmt.Errorf("unknown institution status %q", value.Status)
	}
	if value.Revision < 1 || value.CurrentTerm < 1 || len(value.Terms) != value.CurrentTerm {
		return fmt.Errorf("institution revision or term sequence is inconsistent")
	}
	for i, term := range value.Terms {
		if term.Term != i+1 || term.StartedAt.IsZero() {
			return fmt.Errorf("institution term sequence is inconsistent")
		}
		closed := term.SuspendedAt != nil
		if i+1 < len(value.Terms) && !closed {
			return fmt.Errorf("institution term %d is not closed", term.Term)
		}
		if i+1 == len(value.Terms) {
			if value.Status == model.InstitutionSuspended && !closed {
				return fmt.Errorf("suspended institution has an open term")
			}
			if value.Status == model.InstitutionActive && closed {
				return fmt.Errorf("active institution has a closed term")
			}
		}
	}
	return nil
}

func ValidateBinding(value model.RoleBinding, institutions map[string]model.Institution, certificates map[string]model.Certificate, decoded map[string]*x509.Certificate) error {
	if value.ID == "" {
		return fmt.Errorf("binding needs an id")
	}
	if value.Role != model.RolePrimary && value.Role != model.RoleReviewer {
		return fmt.Errorf("unknown role %q", value.Role)
	}
	if value.Term < 1 {
		return fmt.Errorf("binding term must be positive")
	}
	institution, ok := institutions[value.InstitutionID]
	if !ok {
		return fmt.Errorf("institution is absent")
	}
	if value.Term > institution.CurrentTerm {
		return fmt.Errorf("binding term is beyond the institution's current term")
	}
	if _, ok := certificates[value.CertificateID]; !ok {
		return fmt.Errorf("certificate is absent")
	}
	if decoded != nil {
		cert, ok := decoded[value.CertificateID]
		if !ok {
			return fmt.Errorf("certificate is absent")
		}
		if cert.IsCA {
			return fmt.Errorf("role binding requires an end-entity certificate")
		}
	}
	if value.NotBefore.IsZero() || value.NotAfter.IsZero() || !value.NotAfter.After(value.NotBefore) {
		return fmt.Errorf("binding validity interval is invalid")
	}
	return nil
}

func validateCurrentTermBindings(bindings map[string]model.RoleBinding) error {
	// A certificate may appear in historical terms, but it must not claim two
	// current-term institutions at once. That would make institution identity
	// depend on which binding the caller likes best.
	type key struct {
		cert string
		term int
	}
	seen := map[key]string{}
	// Current-term status is a property of the institution, so this check needs
	// the institution map; it is enforced at binding insertion and repeated by
	// callers that have the map. Structural uniqueness of (certificate, term)
	// across all bindings is still enforced here.
	for id, binding := range bindings {
		k := key{binding.CertificateID, binding.Term}
		if previous, ok := seen[k]; ok {
			return fmt.Errorf("certificate %s is bound twice in term %d (%s and %s)", binding.CertificateID, binding.Term, previous, id)
		}
		seen[k] = id
	}
	return nil
}

func ValidateCombination(value model.EndorsementCombination) error {
	if value.ID == "" || value.Name == "" || len(value.Name) > 200 {
		return fmt.Errorf("combination needs an id and a name")
	}
	if value.Status != model.CombinationActive && value.Status != model.CombinationRetired {
		return fmt.Errorf("unknown combination status %q", value.Status)
	}
	if value.Revision < 1 {
		return fmt.Errorf("combination revision must be positive")
	}
	if len(value.Slots) == 0 || len(value.Slots) > 4 {
		return fmt.Errorf("combination needs one to four role slots")
	}
	roles := map[string]bool{}
	primarySeen := 0
	reviewerSeen := 0
	for _, slot := range value.Slots {
		if slot.Role != model.RolePrimary && slot.Role != model.RoleReviewer {
			return fmt.Errorf("unknown slot role %q", slot.Role)
		}
		if roles[slot.Role] {
			return fmt.Errorf("duplicate slot role %q", slot.Role)
		}
		roles[slot.Role] = true
		if slot.Role == model.RolePrimary {
			if slot.Count != 1 {
				return fmt.Errorf("primary count must be exactly one")
			}
			primarySeen = slot.Count
		} else {
			if slot.Count < 1 || slot.Count > 2 {
				return fmt.Errorf("reviewer count must be one or two")
			}
			reviewerSeen = slot.Count
		}
	}
	// The receiver accepts exactly two shapes: a primary plus one reviewer, or
	// two independent reviewers replacing the primary. This keeps a "sufficient"
	// combination unambiguous and prevents an arbitrary count from being treated
	// as a quorum.
	if !((primarySeen == 1 && reviewerSeen == 1) || (primarySeen == 0 && reviewerSeen == 2)) {
		return fmt.Errorf("combination must be primary+reviewer or two reviewers")
	}
	return nil
}

func ValidateJointDecision(decision model.JointDecision, material model.JointMaterial) error {
	if decision.ID == "" {
		return fmt.Errorf("joint decision needs an id")
	}
	if decision.Request.ArtifactID != material.Artifact.ID ||
		decision.Request.TrustSetID != material.TrustSet.ID ||
		decision.Request.PolicyID != material.Policy.ID ||
		decision.Request.PolicyVersion != material.Policy.Version {
		return fmt.Errorf("joint decision request does not match captured material")
	}
	if decision.TrustRevision != material.TrustSet.Revision {
		return fmt.Errorf("joint decision trust revision does not match captured material")
	}
	if len(decision.Request.SignatureIDs) != len(material.Signatures) || len(decision.Request.CombinationIDs) != len(material.Combinations) {
		return fmt.Errorf("joint decision request does not enumerate captured material")
	}
	for _, id := range decision.Request.SignatureIDs {
		if _, ok := material.Signatures[id]; !ok {
			return fmt.Errorf("joint decision references an absent signature")
		}
	}
	for _, id := range decision.Request.CombinationIDs {
		if _, ok := material.Combinations[id]; !ok {
			return fmt.Errorf("joint decision references an absent combination")
		}
	}
	return nil
}
