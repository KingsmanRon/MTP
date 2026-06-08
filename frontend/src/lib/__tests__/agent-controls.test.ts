import { AGENT_CONTROL_PRESETS, buildActionPolicyLists } from "../agent-controls";

describe("agent controls", () => {
  it("preserves custom actions while applying standard action decisions", () => {
    const result = buildActionPolicyLists(
      ["promptfoo_eval", "api_call"],
      ["repo_change"],
      ["financial_transaction", "api_call"],
    );

    expect(result.allowed_actions).toEqual([
      "promptfoo_eval",
      "financial_transaction",
      "api_call",
    ]);
    expect(result.blocked_actions).toContain("repo_change");
    expect(result.blocked_actions).toContain("admin_action");
    expect(result.blocked_actions).not.toContain("api_call");
  });

  it("ships a bounded spend preset for the primary wedge", () => {
    const spendPreset = AGENT_CONTROL_PRESETS.find((preset) => preset.id === "spend_guard");

    expect(spendPreset?.allowed).toContain("financial_transaction");
    expect(spendPreset?.perActionLimit).toBeLessThanOrEqual(spendPreset?.dailyLimit ?? 0);
  });

  it("locks down every standard action", () => {
    const result = buildActionPolicyLists([], [], []);

    expect(result.allowed_actions).toEqual([]);
    expect(result.blocked_actions).toHaveLength(6);
  });
});
