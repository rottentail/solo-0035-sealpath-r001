package verification

import (
	"crypto/x509"
	"sealpath/internal/codec"
	"sealpath/internal/model"
	"sealpath/internal/policy"
)

// CaptureJoint fixes the artifact, trust set, policy version, signatures,
// institutions, bindings, combinations and compromise records that the decision
// will be judged on. Everything is copied so later updates cannot reach it.
func CaptureJoint(st model.State, request model.JointRequest) (model.JointMaterial, model.JointRequest, error) {
	var out model.JointMaterial
	artifact, ok := st.Artifacts[request.ArtifactID]
	if !ok {
		return out, request, model.Missing("artifact", request.ArtifactID)
	}
	trust, ok := st.TrustSets[request.TrustSetID]
	if !ok {
		return out, request, model.Missing("trust set", request.TrustSetID)
	}
	if trust.Status != "active" {
		return out, request, model.Conflict("trust set is retired")
	}
	p, err := policy.Select(st, request.PolicyID, request.PolicyVersion)
	if err != nil {
		return out, request, err
	}
	request.PolicyVersion = p.Version
	if request.At.IsZero() {
		return out, request, model.Invalid("explicit verification time is required")
	}
	request.At = request.At.UTC()
	if len(request.SignatureIDs) == 0 || len(request.SignatureIDs) > 16 {
		return out, request, model.Invalid("one to sixteen submitted signatures are required")
	}
	signatures := map[string]model.Signature{}
	for _, id := range request.SignatureIDs {
		sig, ok := st.Signatures[id]
		if !ok {
			return out, request, model.Missing("signature", id)
		}
		if sig.ArtifactID != artifact.ID {
			return out, request, model.Invalid("signature %s is bound to another artifact", id)
		}
		if _, exists := signatures[id]; exists {
			return out, request, model.Invalid("duplicate signature id %s", id)
		}
		signatures[id] = sig
	}
	if len(request.CombinationIDs) == 0 || len(request.CombinationIDs) > 16 {
		return out, request, model.Invalid("one to sixteen endorsement combinations are required")
	}
	combinations := map[string]model.EndorsementCombination{}
	for _, id := range request.CombinationIDs {
		value, ok := st.Combinations[id]
		if !ok {
			return out, request, model.Missing("endorsement combination", id)
		}
		if value.Status != model.CombinationActive {
			return out, request, model.Conflict("endorsement combination is retired")
		}
		if _, exists := combinations[id]; exists {
			return out, request, model.Invalid("duplicate combination id %s", id)
		}
		combinations[id] = value
	}
	out = model.JointMaterial{
		Artifact:     artifact,
		TrustSet:     trust,
		Policy:       p,
		Signatures:   signatures,
		Certificates: map[string]model.Certificate{},
		Revocations:  map[string]model.RevocationList{},
		Institutions: map[string]model.Institution{},
		Bindings:     map[string]model.RoleBinding{},
		Combinations: combinations,
		Compromises:  map[string]model.Compromise{},
	}
	if err := scopeJointMaterial(&out, st); err != nil {
		return out, request, err
	}
	return out, request, nil
}

// scopeJointMaterial narrows the captured corpus. A joint decision needs the
// certificate chains and revocation lists that the submitted endorsements use,
// plus every role relation and compromise record of the institutions involved:
// without those, an alternative combination could hide an institution-wide
// finding. Unrelated end-entity certificates stay out of the bundle so the
// disclosure reported per combination is meaningful.
func scopeJointMaterial(out *model.JointMaterial, st model.State) error {
	parsed := map[string]*x509.Certificate{}
	for id, value := range st.Certificates {
		cert, err := codec.ParseCertificate(value.DER)
		if err != nil {
			return err
		}
		if cert.Raw == nil || codec.Digest(value.DER) != id {
			return model.Invalid("certificate material %s is inconsistent", id)
		}
		parsed[id] = cert
	}
	relevantInstitutions := map[string]bool{}
	for _, sig := range out.Signatures {
		for _, binding := range st.RoleBindings {
			if binding.CertificateID == sig.CertificateID {
				relevantInstitutions[binding.InstitutionID] = true
			}
		}
	}
	bindings := map[string]model.RoleBinding{}
	certificateIDs := map[string]bool{}
	// All CA certificates stay available as path material; they are not
	// endorsements and cannot substitute for one.
	for id, cert := range parsed {
		if cert.IsCA {
			certificateIDs[id] = true
		}
	}
	for id, binding := range st.RoleBindings {
		if !relevantInstitutions[binding.InstitutionID] {
			continue
		}
		bindings[id] = binding
		certificateIDs[binding.CertificateID] = true
	}
	for _, sig := range out.Signatures {
		certificateIDs[sig.CertificateID] = true
	}
	for id := range certificateIDs {
		value, ok := st.Certificates[id]
		if !ok {
			return model.Invalid("captured certificate %s is absent", id)
		}
		out.Certificates[id] = value
	}
	for id, value := range st.Institutions {
		if relevantInstitutions[id] {
			out.Institutions[id] = value
		}
	}
	out.Bindings = bindings
	for id, value := range st.Compromises {
		if certificateIDs[id] {
			out.Compromises[id] = value
		}
	}
	for id, value := range st.Revocations {
		if certificateIDs[value.IssuerID] {
			out.Revocations[id] = value
		}
	}
	return nil
}
