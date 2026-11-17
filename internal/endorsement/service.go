package endorsement

import (
	"fmt"
	"sealpath/internal/codec"
	"sealpath/internal/jointvalidate"
	"sealpath/internal/model"
	"sealpath/internal/repository"
	"sort"
	"time"
)

type Service struct{ Store *repository.Store }

type InstitutionRequest struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	StartedAt        time.Time `json:"started_at"`
	ExpectedRevision int       `json:"expected_revision"`
}

func (s Service) PutInstitution(input InstitutionRequest) (model.Institution, error) {
	var out model.Institution
	if err := model.ValidateID(input.ID); err != nil {
		return out, err
	}
	if input.Name == "" || len(input.Name) > 200 {
		return out, model.Invalid("institution name must contain 1-200 characters")
	}
	err := s.Store.Update("institution.revised", input.ID, func(st *model.State) error {
		current, exists := st.Institutions[input.ID]
		if current.Revision != input.ExpectedRevision {
			return model.Conflict("institution revision changed")
		}
		now := time.Now().UTC()
		if !exists {
			started := input.StartedAt.UTC()
			if started.IsZero() {
				started = now
			}
			if started.After(now) {
				return model.Invalid("institution start time cannot be in the future")
			}
			out = model.Institution{ID: input.ID, Name: input.Name, Status: model.InstitutionActive, CurrentTerm: 1, Terms: []model.InstitutionTerm{{Term: 1, StartedAt: started}}, Revision: 1, CreatedAt: now, UpdatedAt: now}
		} else {
			current.Name = input.Name
			current.Revision++
			current.UpdatedAt = now
			out = current
		}
		st.Institutions[out.ID] = out
		return nil
	})
	return out, err
}

type StatusRequest struct {
	At               time.Time `json:"at"`
	ExpectedRevision int       `json:"expected_revision"`
}

func (s Service) Suspend(id string, input StatusRequest) (model.Institution, error) {
	var out model.Institution
	revision := input.ExpectedRevision
	err := s.Store.Update("institution.suspended", id, func(st *model.State) error {
		current, ok := st.Institutions[id]
		if !ok {
			return model.Missing("institution", id)
		}
		if current.Revision != revision {
			return model.Conflict("institution revision changed")
		}
		if current.Status == model.InstitutionSuspended {
			return model.Conflict("institution is already suspended")
		}
		now := time.Now().UTC()
		at := input.At.UTC()
		if at.IsZero() {
			at = now
		}
		last := current.Terms[len(current.Terms)-1]
		if at.Before(last.StartedAt) {
			return model.Invalid("suspension cannot precede the current term")
		}
		if at.After(now) {
			return model.Invalid("suspension time cannot be in the future")
		}
		current.Status = model.InstitutionSuspended
		current.Revision++
		current.UpdatedAt = now
		current.Terms[len(current.Terms)-1].SuspendedAt = &at
		out = current
		st.Institutions[id] = current
		return nil
	})
	return out, err
}

func (s Service) Reinstate(id string, input StatusRequest) (model.Institution, error) {
	var out model.Institution
	revision := input.ExpectedRevision
	err := s.Store.Update("institution.reinstated", id, func(st *model.State) error {
		current, ok := st.Institutions[id]
		if !ok {
			return model.Missing("institution", id)
		}
		if current.Revision != revision {
			return model.Conflict("institution revision changed")
		}
		if current.Status != model.InstitutionSuspended {
			return model.Conflict("institution is not suspended")
		}
		now := time.Now().UTC()
		at := input.At.UTC()
		if at.IsZero() {
			at = now
		}
		closed := current.Terms[len(current.Terms)-1].SuspendedAt
		if closed == nil || at.Before(*closed) {
			return model.Invalid("reinstatement cannot precede the suspension")
		}
		if at.After(now) {
			return model.Invalid("reinstatement time cannot be in the future")
		}
		current.Status = model.InstitutionActive
		current.Revision++
		current.UpdatedAt = now
		current.CurrentTerm++
		current.Terms = append(current.Terms, model.InstitutionTerm{Term: current.CurrentTerm, StartedAt: at})
		out = current
		st.Institutions[id] = current
		return nil
	})
	return out, err
}

type BindingRequest struct {
	ID            string    `json:"id"`
	InstitutionID string    `json:"institution_id"`
	CertificateID string    `json:"certificate_id"`
	Role          string    `json:"role"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	Term          int       `json:"term"`
}

func (s Service) Bind(input BindingRequest) (model.RoleBinding, error) {
	var out model.RoleBinding
	if err := model.ValidateID(input.ID); err != nil {
		return out, err
	}
	if input.Role != model.RolePrimary && input.Role != model.RoleReviewer {
		return out, model.Invalid("role must be primary or reviewer")
	}
	if input.NotBefore.IsZero() || input.NotAfter.IsZero() || !input.NotAfter.After(input.NotBefore) {
		return out, model.Invalid("binding not_before and not_after must define a positive interval")
	}
	input.NotBefore = input.NotBefore.UTC()
	input.NotAfter = input.NotAfter.UTC()
	err := s.Store.Update("role.bound", input.ID, func(st *model.State) error {
		institution, ok := st.Institutions[input.InstitutionID]
		if !ok {
			return model.Missing("institution", input.InstitutionID)
		}
		if _, ok := st.Certificates[input.CertificateID]; !ok {
			return model.Missing("certificate", input.CertificateID)
		}
		cert, err := codec.ParseCertificate(st.Certificates[input.CertificateID].DER)
		if err != nil {
			return err
		}
		if cert.IsCA {
			return model.Invalid("role binding requires an end-entity certificate")
		}
		if input.NotBefore.Before(cert.NotBefore) || input.NotAfter.After(cert.NotAfter) {
			return model.Invalid("binding interval must fall inside the certificate validity interval")
		}
		term := input.Term
		if term == 0 {
			term = institution.CurrentTerm
		}
		if term < 1 || term > institution.CurrentTerm {
			return model.Invalid("binding term is not an existing institution term")
		}
		// Bindings for the current term require the institution to be active.
		// Historical terms stay bindable for explainability of earlier decisions.
		if term == institution.CurrentTerm && institution.Status != model.InstitutionActive {
			return model.Conflict("institution is suspended; bind into a new term after reinstatement")
		}
		value := model.RoleBinding{ID: input.ID, InstitutionID: input.InstitutionID, CertificateID: input.CertificateID, Role: input.Role, Term: term, NotBefore: input.NotBefore, NotAfter: input.NotAfter, ReceivedAt: time.Now().UTC()}
		if old, ok := st.RoleBindings[input.ID]; ok {
			if old.InstitutionID != value.InstitutionID || old.CertificateID != value.CertificateID || old.Role != value.Role || old.Term != value.Term || !old.NotBefore.Equal(value.NotBefore) || !old.NotAfter.Equal(value.NotAfter) {
				return model.Conflict("role binding id already exists with different content")
			}
			out = old
			return nil
		}
		for id, existing := range st.RoleBindings {
			if existing.CertificateID == value.CertificateID && existing.Term == value.Term {
				return model.Conflict(fmt.Sprintf("certificate is already bound as %s in term %d by binding %s", existing.Role, existing.Term, id))
			}
			// A renewal or a cross-issued certificate for the same institution,
			// role and term is allowed only when its interval does not overlap an
			// existing relation. Overlap would make one institution appear twice
			// in the same role, and the choice of certificate would silently
			// decide which institution identity applies.
			if existing.InstitutionID == value.InstitutionID && existing.Role == value.Role && existing.Term == value.Term && intervalsOverlap(existing, value) {
				return model.Conflict(fmt.Sprintf("institution %s already holds role %s in term %d through binding %s; renewal intervals must not overlap", value.InstitutionID, value.Role, value.Term, id))
			}
		}
		out = value
		st.RoleBindings[out.ID] = out
		return nil
	})
	return out, err
}

type CombinationRequest struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	Slots            []model.RoleSlot `json:"slots"`
	ExpectedRevision int              `json:"expected_revision"`
}

func (s Service) PutCombination(input CombinationRequest) (model.EndorsementCombination, error) {
	var out model.EndorsementCombination
	if err := model.ValidateID(input.ID); err != nil {
		return out, err
	}
	slots := append([]model.RoleSlot(nil), input.Slots...)
	sort.Slice(slots, func(i, j int) bool { return slots[i].Role < slots[j].Role })
	value := model.EndorsementCombination{ID: input.ID, Name: input.Name, Slots: slots, Status: model.CombinationActive, Revision: input.ExpectedRevision + 1, UpdatedAt: time.Now().UTC()}
	if err := jointvalidate.ValidateCombination(value); err != nil {
		return out, model.Invalid("%v", err)
	}
	err := s.Store.Update("combination.revised", input.ID, func(st *model.State) error {
		current, exists := st.Combinations[input.ID]
		if current.Revision != input.ExpectedRevision {
			return model.Conflict("combination revision changed")
		}
		if exists && current.Status == model.CombinationRetired {
			return model.Conflict("retired combination cannot be edited")
		}
		if exists {
			value.CreatedAt = current.CreatedAt
		} else {
			value.CreatedAt = value.UpdatedAt
		}
		out = value
		st.Combinations[out.ID] = out
		return nil
	})
	return out, err
}

func (s Service) RetireCombination(id string, revision int) (model.EndorsementCombination, error) {
	var out model.EndorsementCombination
	err := s.Store.Update("combination.retired", id, func(st *model.State) error {
		current, ok := st.Combinations[id]
		if !ok {
			return model.Missing("combination", id)
		}
		if current.Revision != revision {
			return model.Conflict("combination revision changed")
		}
		if current.Status == model.CombinationRetired {
			return model.Conflict("combination is already retired")
		}
		current.Status = model.CombinationRetired
		current.Revision++
		current.UpdatedAt = time.Now().UTC()
		out = current
		st.Combinations[id] = current
		return nil
	})
	return out, err
}

type CompromiseRequest struct {
	CertificateID string    `json:"certificate_id"`
	EffectiveAt   time.Time `json:"effective_at"`
	Reason        string    `json:"reason"`
}

// RecordCompromise marks a certificate as untrustworthy from EffectiveAt. It is
// deliberately keyed by certificate so a later verification cannot escape the
// finding merely by selecting a different combination that uses another
// certificate from the same institution.
func (s Service) RecordCompromise(input CompromiseRequest) (model.Compromise, error) {
	var out model.Compromise
	if input.Reason == "" || len(input.Reason) > 500 {
		return out, model.Invalid("compromise reason must contain 1-500 characters")
	}
	if input.EffectiveAt.IsZero() {
		return out, model.Invalid("compromise effective_at is required")
	}
	input.EffectiveAt = input.EffectiveAt.UTC()
	err := s.Store.Update("compromise.recorded", input.CertificateID, func(st *model.State) error {
		if _, ok := st.Certificates[input.CertificateID]; !ok {
			return model.Missing("certificate", input.CertificateID)
		}
		existing, ok := st.Compromises[input.CertificateID]
		if ok {
			// A later finding can only move the effective time earlier; moving it
			// later would silently excuse endorsements already known to be bad.
			if existing.EffectiveAt.Before(input.EffectiveAt) {
				return model.Conflict("existing compromise takes effect earlier and cannot be weakened")
			}
			if existing.EffectiveAt.Equal(input.EffectiveAt) && existing.Reason == input.Reason {
				out = existing
				return nil
			}
		}
		out = model.Compromise{CertificateID: input.CertificateID, EffectiveAt: input.EffectiveAt, Reason: input.Reason, RecordedAt: time.Now().UTC()}
		st.Compromises[input.CertificateID] = out
		return nil
	})
	return out, err
}

func intervalsOverlap(a, b model.RoleBinding) bool {
	return a.NotBefore.Before(b.NotAfter) && b.NotBefore.Before(a.NotAfter)
}
