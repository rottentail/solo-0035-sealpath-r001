package transport

import (
	"net/http"
	"sealpath/internal/endorsement"
	"sealpath/internal/model"
	"sort"
)

func (s *Server) putInstitution(w http.ResponseWriter, r *http.Request) {
	var input endorsement.InstitutionRequest
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.Endorsement.PutInstitution(input)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, out)
}

func (s *Server) listInstitutions(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	values := []model.Institution{}
	for _, value := range state.Institutions {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	writeJSON(w, 200, values)
}

func (s *Server) getInstitution(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	value, ok := state.Institutions[r.PathValue("id")]
	if !ok {
		s.fail(w, model.Missing("institution", r.PathValue("id")))
		return
	}
	writeJSON(w, 200, value)
}

func (s *Server) suspendInstitution(w http.ResponseWriter, r *http.Request) {
	s.changeInstitutionStatus(w, r, s.Endorsement.Suspend)
}

func (s *Server) reinstateInstitution(w http.ResponseWriter, r *http.Request) {
	s.changeInstitutionStatus(w, r, s.Endorsement.Reinstate)
}

func (s *Server) changeInstitutionStatus(w http.ResponseWriter, r *http.Request, change func(string, endorsement.StatusRequest) (model.Institution, error)) {
	var input endorsement.StatusRequest
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := change(r.PathValue("id"), input)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) bindRole(w http.ResponseWriter, r *http.Request) {
	var input endorsement.BindingRequest
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.Endorsement.Bind(input)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, out)
}

func (s *Server) listRoleBindings(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	values := []model.RoleBinding{}
	for _, value := range state.RoleBindings {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].InstitutionID != values[j].InstitutionID {
			return values[i].InstitutionID < values[j].InstitutionID
		}
		if values[i].Term != values[j].Term {
			return values[i].Term < values[j].Term
		}
		return values[i].ID < values[j].ID
	})
	writeJSON(w, 200, values)
}

func (s *Server) putCombination(w http.ResponseWriter, r *http.Request) {
	var input endorsement.CombinationRequest
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.Endorsement.PutCombination(input)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, out)
}

func (s *Server) listCombinations(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	values := []model.EndorsementCombination{}
	for _, value := range state.Combinations {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	writeJSON(w, 200, values)
}

func (s *Server) retireCombination(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ExpectedRevision int `json:"expected_revision"`
	}
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.Endorsement.RetireCombination(r.PathValue("id"), input.ExpectedRevision)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) recordCompromise(w http.ResponseWriter, r *http.Request) {
	var input endorsement.CompromiseRequest
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.Endorsement.RecordCompromise(input)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, out)
}

func (s *Server) listCompromises(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	values := []model.Compromise{}
	for _, value := range state.Compromises {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].CertificateID < values[j].CertificateID })
	writeJSON(w, 200, values)
}
