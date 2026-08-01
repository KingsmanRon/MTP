import { assessPilotRisk, PILOT_RISK_SIGNALS } from "../pilot-risk";

describe("pilot risk assessment", () => {
  it("prioritizes financial actions as the recommended pilot workflow", () => {
    const assessment = assessPilotRisk([
      "financial_actions",
      "authorization_gap",
      "tamper_evidence_gap",
      "security_review_blocked",
    ]);

    expect(assessment.level).toBe("priority");
    expect(assessment.recommendedWorkflow).toBe("Agent spend and payment authorisation");
    expect(assessment.score).toBe(11);
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

  /* The site is payments-led. A visitor who answers only the payments question
     must not be filtered out of the funnel or recommended a different pilot. */
  describe("payments-led ordering", () => {
    it("asks the payments question first", () => {
      expect(PILOT_RISK_SIGNALS[0].id).toBe("financial_actions");
    });

    it("weights payments above every other signal", () => {
      const payments = PILOT_RISK_SIGNALS.find((s) => s.id === "financial_actions")!;
      const others = PILOT_RISK_SIGNALS.filter((s) => s.id !== "financial_actions");
      expect(others.every((s) => s.weight < payments.weight)).toBe(true);
    });

    it("qualifies a payments-only answer as a pilot candidate", () => {
      const assessment = assessPilotRisk(["financial_actions"]);

      expect(assessment.level).toBe("candidate");
      expect(assessment.recommendedWorkflow).toBe("Agent spend and payment authorisation");
    });
  });
});
