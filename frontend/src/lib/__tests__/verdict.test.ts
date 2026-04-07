import { verdictLabel, isPassVerdict, isEscalateVerdict } from "../verdict";

describe("verdict mapping (presentation layer)", () => {
  it("maps backend enums to canonical UI labels", () => {
    expect(verdictLabel("approved")).toBe("PASS");
    expect(verdictLabel("blocked")).toBe("BLOCK");
    expect(verdictLabel("rate_limited")).toBe("ESCALATE");
    expect(verdictLabel("signature_invalid")).toBe("BLOCK");
  });

  it("falls back to BLOCK for unknown verdicts (fail-closed)", () => {
    expect(verdictLabel("something_else")).toBe("BLOCK");
    expect(verdictLabel("")).toBe("BLOCK");
  });

  it("identifies pass and escalate verdicts via predicates", () => {
    expect(isPassVerdict("approved")).toBe(true);
    expect(isPassVerdict("blocked")).toBe(false);
    expect(isEscalateVerdict("rate_limited")).toBe(true);
    expect(isEscalateVerdict("approved")).toBe(false);
    expect(isEscalateVerdict("blocked")).toBe(false);
  });
});
