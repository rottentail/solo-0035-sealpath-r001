package model

import "time"

const (
	RolePrimary  = "primary"
	RoleReviewer = "reviewer"
)

const (
	InstitutionActive    = "active"
	InstitutionSuspended = "suspended"
)

const (
	CombinationActive  = "active"
	CombinationRetired = "retired"
)

const (
	EndorsementEligible    = "eligible"
	EndorsementProvisional = "provisional"
	EndorsementFailed      = "failed"
)

// Failure scopes state how far an observed failure reaches. A candidate-scope
// failure only disqualifies the certificate/signature that produced it. A
// binding-scope failure disqualifies one role relation. An institution-scope
// failure disqualifies every endorsement by that institution, regardless of
// which certificate or renewal happens to still verify.
const (
	ScopeCandidate   = "candidate"
	ScopeBinding     = "binding"
	ScopeInstitution = "institution"
	ScopeCombination = "combination"
)

// InstitutionTerm scopes role bindings. A suspension closes the current term;
// a reinstatement opens a new term. Bindings never move between terms, so a
// new endorsement cannot mix role relations that existed on opposite sides of
// a suspension.
type InstitutionTerm struct {
	Term        int        `json:"term"`
	StartedAt   time.Time  `json:"started_at"`
	SuspendedAt *time.Time `json:"suspended_at,omitempty"`
}

type Institution struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Status      string            `json:"status"`
	CurrentTerm int               `json:"current_term"`
	Terms       []InstitutionTerm `json:"terms"`
	Revision    int               `json:"revision"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// RoleBinding is the receiver's explicit statement that a certificate acts for
// an institution in one role for one term. Institution identity is never read
// from the certificate subject or issuer text.
type RoleBinding struct {
	ID            string    `json:"id"`
	InstitutionID string    `json:"institution_id"`
	CertificateID string    `json:"certificate_id"`
	Role          string    `json:"role"`
	Term          int       `json:"term"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	ReceivedAt    time.Time `json:"received_at"`
}

type RoleSlot struct {
	Role  string `json:"role"`
	Count int    `json:"count"`
}

// EndorsementCombination is a receiver-maintained quorum profile. Every slot
// must be filled by a distinct institution; one institution can never cast
// more than one vote in a combination.
type EndorsementCombination struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Slots     []RoleSlot `json:"slots"`
	Status    string     `json:"status"`
	Revision  int        `json:"revision"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Compromise is evidence that a certificate is no longer trustworthy from
// EffectiveAt onward. It is recorded against a certificate but has
// institution-wide effect once that certificate is bound to an institution.
type Compromise struct {
	CertificateID string    `json:"certificate_id"`
	EffectiveAt   time.Time `json:"effective_at"`
	Reason        string    `json:"reason"`
	RecordedAt    time.Time `json:"recorded_at"`
}

type JointRequest struct {
	ArtifactID     string    `json:"artifact_id"`
	TrustSetID     string    `json:"trust_set_id"`
	PolicyID       string    `json:"policy_id"`
	PolicyVersion  int       `json:"policy_version"`
	SignatureIDs   []string  `json:"signature_ids"`
	CombinationIDs []string  `json:"combination_ids"`
	At             time.Time `json:"at"`
}

// JointMaterial is the complete, captured basis of a joint decision. Later
// institution, binding, combination, compromise or CRL changes cannot rewrite
// it.
type JointMaterial struct {
	Artifact     Artifact                          `json:"artifact"`
	TrustSet     TrustSet                          `json:"trust_set"`
	Policy       Policy                            `json:"policy"`
	Signatures   map[string]Signature              `json:"signatures"`
	Certificates map[string]Certificate            `json:"certificates"`
	Revocations  map[string]RevocationList         `json:"revocations"`
	Institutions map[string]Institution            `json:"institutions"`
	Bindings     map[string]RoleBinding            `json:"bindings"`
	Combinations map[string]EndorsementCombination `json:"combinations"`
	Compromises  map[string]Compromise             `json:"compromises"`
}

type EndorsementOutcome struct {
	SignatureID   string   `json:"signature_id"`
	CertificateID string   `json:"certificate_id"`
	InstitutionID string   `json:"institution_id,omitempty"`
	BindingID     string   `json:"binding_id,omitempty"`
	Role          string   `json:"role,omitempty"`
	Term          int      `json:"term,omitempty"`
	Status        string   `json:"status"`
	FailureScope  string   `json:"failure_scope,omitempty"`
	ReasonCode    string   `json:"reason_code,omitempty"`
	Detail        string   `json:"detail,omitempty"`
	Path          []string `json:"path"`
	Revocations   []string `json:"revocations"`
	Checks        []Check  `json:"checks"`
}

type InstitutionFinding struct {
	InstitutionID string   `json:"institution_id"`
	Name          string   `json:"name"`
	Term          int      `json:"term,omitempty"`
	Status        string   `json:"status"`
	FailureScope  string   `json:"failure_scope,omitempty"`
	ReasonCode    string   `json:"reason_code,omitempty"`
	Detail        string   `json:"detail,omitempty"`
	Certificates  []string `json:"certificates"`
}

type Assignment struct {
	SlotRole      string `json:"slot_role"`
	InstitutionID string `json:"institution_id"`
	SignatureID   string `json:"signature_id"`
	CertificateID string `json:"certificate_id"`
	Term          int    `json:"term"`
}

type Disclosure struct {
	Institutions []string `json:"institutions"`
	Certificates []string `json:"certificates"`
	Signatures   []string `json:"signatures"`
	Revocations  []string `json:"revocations"`
	Score        int      `json:"score"`
}

type CombinationOutcome struct {
	CombinationID string       `json:"combination_id"`
	Status        string       `json:"status"`
	Selected      bool         `json:"selected"`
	Assignments   []Assignment `json:"assignments"`
	Disclosure    Disclosure   `json:"disclosure"`
	Reasons       []Check      `json:"reasons"`
}

type JointDecision struct {
	ID                  string               `json:"id"`
	Verdict             string               `json:"verdict"`
	Request             JointRequest         `json:"request"`
	TrustRevision       int                  `json:"trust_revision"`
	SelectedCombination string               `json:"selected_combination,omitempty"`
	Endorsements        []EndorsementOutcome `json:"endorsements"`
	Institutions        []InstitutionFinding `json:"institutions"`
	Combinations        []CombinationOutcome `json:"combinations"`
	Checks              []Check              `json:"checks"`
	Warnings            []Check              `json:"warnings"`
	CreatedAt           time.Time            `json:"created_at"`
	MaterialHash        string               `json:"material_hash"`
}

type JointBundle struct {
	Format   string        `json:"format"`
	Decision JointDecision `json:"decision"`
	Material JointMaterial `json:"material"`
	Digest   string        `json:"digest"`
}
