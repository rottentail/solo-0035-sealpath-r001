package transport

import (
	"errors"
	"log/slog"
	"net/http"
	"sealpath/internal/artifact"
	"sealpath/internal/authority"
	"sealpath/internal/endorsement"
	"sealpath/internal/evidence"
	"sealpath/internal/model"
	"sealpath/internal/policy"
	"sealpath/internal/repository"
	"sealpath/internal/revocation"
	"sealpath/internal/signature"
	"sealpath/internal/verification"
	"time"
)

type Server struct {
	Store       *repository.Store
	Authority   authority.Service
	Artifacts   artifact.Service
	Signatures  signature.Service
	Revocations revocation.Service
	Policies    policy.Service
	Verifier    verification.Service
	Endorsement endorsement.Service
	Evidence    evidence.Service
	Logger      *slog.Logger
}

func New(store *repository.Store, logger *slog.Logger) *Server {
	return &Server{Store: store, Authority: authority.Service{Store: store}, Artifacts: artifact.Service{Store: store}, Signatures: signature.Service{Store: store}, Revocations: revocation.Service{Store: store}, Policies: policy.Service{Store: store}, Verifier: verification.Service{Store: store}, Endorsement: endorsement.Service{Store: store}, Evidence: evidence.Service{Store: store}, Logger: logger}
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("POST /v1/certificates", s.importCertificate)
	mux.HandleFunc("GET /v1/certificates", s.listCertificates)
	mux.HandleFunc("GET /v1/certificates/{id}", s.getCertificate)
	mux.HandleFunc("POST /v1/trust-sets", s.putTrust)
	mux.HandleFunc("GET /v1/trust-sets", s.listTrust)
	mux.HandleFunc("POST /v1/trust-sets/{id}/retire", s.retireTrust)
	mux.HandleFunc("POST /v1/artifacts", s.importArtifact)
	mux.HandleFunc("GET /v1/artifacts/{id}", s.getArtifact)
	mux.HandleFunc("POST /v1/signatures", s.importSignature)
	mux.HandleFunc("GET /v1/signatures/{id}", s.getSignature)
	mux.HandleFunc("POST /v1/revocations", s.importCRL)
	mux.HandleFunc("GET /v1/revocations", s.listCRLs)
	mux.HandleFunc("POST /v1/policies", s.createPolicy)
	mux.HandleFunc("GET /v1/policies/{id}", s.getPolicies)
	mux.HandleFunc("POST /v1/decisions", s.verify)
	mux.HandleFunc("GET /v1/decisions", s.listDecisions)
	mux.HandleFunc("GET /v1/decisions/{id}", s.getDecision)
	mux.HandleFunc("GET /v1/decisions/{id}/bundle", s.exportBundle)
	mux.HandleFunc("POST /v1/evidence/replay", s.replay)
	mux.HandleFunc("GET /v1/evidence/compare", s.compare)
	mux.HandleFunc("GET /v1/events", s.events)
	mux.HandleFunc("POST /v1/institutions", s.putInstitution)
	mux.HandleFunc("GET /v1/institutions", s.listInstitutions)
	mux.HandleFunc("GET /v1/institutions/{id}", s.getInstitution)
	mux.HandleFunc("POST /v1/institutions/{id}/suspend", s.suspendInstitution)
	mux.HandleFunc("POST /v1/institutions/{id}/reinstate", s.reinstateInstitution)
	mux.HandleFunc("POST /v1/role-bindings", s.bindRole)
	mux.HandleFunc("GET /v1/role-bindings", s.listRoleBindings)
	mux.HandleFunc("POST /v1/endorsement-combinations", s.putCombination)
	mux.HandleFunc("GET /v1/endorsement-combinations", s.listCombinations)
	mux.HandleFunc("POST /v1/endorsement-combinations/{id}/retire", s.retireCombination)
	mux.HandleFunc("POST /v1/compromises", s.recordCompromise)
	mux.HandleFunc("GET /v1/compromises", s.listCompromises)
	mux.HandleFunc("POST /v1/joint-decisions", s.verifyJoint)
	mux.HandleFunc("GET /v1/joint-decisions", s.listJointDecisions)
	mux.HandleFunc("GET /v1/joint-decisions/{id}", s.getJointDecision)
	mux.HandleFunc("GET /v1/joint-decisions/{id}/bundle", s.exportJointBundle)
	mux.HandleFunc("POST /v1/joint-evidence/replay", s.replayJoint)
	mux.HandleFunc("GET /v1/joint-evidence/compare", s.compareJoint)
	return s.middleware(mux)
}
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		defer func() {
			if value := recover(); value != nil {
				s.Logger.Error("request panic", "path", r.URL.Path)
				s.fail(w, errors.New("internal failure"))
			}
			s.Logger.Info("request", "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(started).Milliseconds())
		}()
		r.Body = http.MaxBytesReader(w, r.Body, 16*1024*1024)
		next.ServeHTTP(w, r)
	})
}
func (s *Server) fail(w http.ResponseWriter, err error) {
	var expected *model.Error
	if errors.As(err, &expected) {
		writeJSON(w, expected.HTTP, map[string]any{"error": expected.Code, "message": expected.Message})
		return
	}
	s.Logger.Error("request failed", "error", err.Error())
	writeJSON(w, 500, map[string]any{"error": "internal_error", "message": "operation could not be completed"})
}
