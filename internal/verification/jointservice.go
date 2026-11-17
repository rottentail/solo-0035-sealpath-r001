package verification

import "sealpath/internal/model"

func (s Service) VerifyJoint(request model.JointRequest) (model.JointDecision, error) {
	var out model.JointDecision
	// Capture and decide under one repository revision so no institution,
	// binding, combination, compromise or CRL edit can intervene.
	err := s.Store.Update("joint_decision.recorded", request.ArtifactID, func(st *model.State) error {
		material, pinned, err := CaptureJoint(*st, request)
		if err != nil {
			return err
		}
		out, err = EvaluateJoint(material, pinned)
		if err != nil {
			return err
		}
		if old, ok := st.JointDecisions[out.ID]; ok {
			out = old
			return nil
		}
		st.JointDecisions[out.ID] = out
		st.JointMaterials[out.ID] = material
		return nil
	})
	return out, err
}
