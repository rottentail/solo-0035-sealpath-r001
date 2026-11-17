package repository

import (
	"fmt"
	"sealpath/internal/codec"
	"sealpath/internal/jointvalidate"
	"sealpath/internal/model"
)

// validateJointState re-checks the endorsement layer at startup. It verifies
// that bindings point at real institutions and certificates, that combinations
// keep their role shape, and that every stored joint decision matches the
// material it captured.
func validateJointState(s model.State) error {
	for id, value := range s.Institutions {
		if err := jointvalidate.ValidateInstitution(value); err != nil {
			return fmt.Errorf("institution %s is inconsistent: %v", id, err)
		}
		if value.ID != id {
			return fmt.Errorf("institution identity mismatch %s", id)
		}
	}
	decoded, err := codec.DecodeCertificates(s.Certificates)
	if err != nil {
		return err
	}
	for id, binding := range s.RoleBindings {
		if err := jointvalidate.ValidateBinding(binding, s.Institutions, s.Certificates, decoded); err != nil {
			return fmt.Errorf("role binding %s is inconsistent: %v", id, err)
		}
		if binding.ID != id {
			return fmt.Errorf("role binding identity mismatch %s", id)
		}
	}
	for id, value := range s.Combinations {
		if err := jointvalidate.ValidateCombination(value); err != nil {
			return fmt.Errorf("endorsement combination %s is inconsistent: %v", id, err)
		}
		if value.ID != id {
			return fmt.Errorf("endorsement combination identity mismatch %s", id)
		}
	}
	for id, value := range s.Compromises {
		if _, ok := s.Certificates[id]; !ok {
			return fmt.Errorf("compromise references a missing certificate %s", id)
		}
		if value.CertificateID != id || value.EffectiveAt.IsZero() || value.Reason == "" {
			return fmt.Errorf("compromise %s is inconsistent", id)
		}
	}
	for id, decision := range s.JointDecisions {
		material, ok := s.JointMaterials[id]
		if !ok || decision.ID != id {
			return fmt.Errorf("joint decision evidence mismatch %s", id)
		}
		hash, err := codec.JSONDigest(material)
		if err != nil || decision.MaterialHash != hash {
			return fmt.Errorf("joint decision material hash mismatch %s", id)
		}
		if err := jointvalidate.ValidateJointDecision(decision, material); err != nil {
			return fmt.Errorf("joint decision %s is inconsistent: %v", id, err)
		}
	}
	return nil
}
