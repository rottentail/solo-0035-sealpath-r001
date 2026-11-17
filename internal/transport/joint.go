package transport

import (
	"net/http"
	"sealpath/internal/evidence"
	"sealpath/internal/model"
	"sort"
)

func (s *Server) verifyJoint(w http.ResponseWriter, r *http.Request) {
	var input model.JointRequest
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.Verifier.VerifyJoint(input)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, out)
}

func (s *Server) listJointDecisions(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	limit, after, err := page(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	ids := []string{}
	for id := range state.JointDecisions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if after > len(ids) {
		after = len(ids)
	}
	end := after + limit
	if end > len(ids) {
		end = len(ids)
	}
	values := []model.JointDecision{}
	for _, id := range ids[after:end] {
		values = append(values, state.JointDecisions[id])
	}
	writeJSON(w, 200, values)
}

func (s *Server) getJointDecision(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	value, ok := state.JointDecisions[r.PathValue("id")]
	if !ok {
		s.fail(w, model.Missing("joint decision", r.PathValue("id")))
		return
	}
	writeJSON(w, 200, value)
}

func (s *Server) exportJointBundle(w http.ResponseWriter, r *http.Request) {
	out, err := s.Evidence.ExportJoint(r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) replayJoint(w http.ResponseWriter, r *http.Request) {
	var input model.JointBundle
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := evidence.ReplayJoint(input)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) compareJoint(w http.ResponseWriter, r *http.Request) {
	out, err := s.Evidence.CompareJoint(r.URL.Query().Get("left"), r.URL.Query().Get("right"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, out)
}
