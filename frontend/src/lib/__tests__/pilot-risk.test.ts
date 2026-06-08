import { assessPilotRisk } from "../pilot-risk";

describe("pilot risk assessment", () => {
  it("prioritizes financial actions as the recommended pilot workflow", () => {
    const assessment = assessPilotRisk([
      "financial_actions",
      "authorization_gap",
      "tamper_evidence_gap",
      "security_review_blocked",
    ]);

    expect(assessment.level).toBe("priority");
    expect(assessment.recommendedWorkflow).toBe("Agent spend and payment authorization");
    expect(assessment.score).toBe(10);
  });

  it("identifies a concrete production-change pilot candidate", () => {
    const assessment = assessPilotRisk(["production_changes", "authorization_gap"]);

    expect(assessment.level).toBe("candidate");
    expect(assessment.recommendedWorkflow).toBe("Production change control");
  });

  it("keeps low-exposure teams in discovery", () => {
    const assessment = assessPilotRisk(["external_tools"]);

    expect(assessment.level).toBe("observe");
    expect(assessment.score).toBe(1);
  });
});
