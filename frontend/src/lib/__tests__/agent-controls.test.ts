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
    expect(result.blocked_actions).toHaveLength(10);
  });

  it("ships a code and release preset that blocks merge and deployment", () => {
    const preset = AGENT_CONTROL_PRESETS.find((candidate) => candidate.id === "code_release_guard");

    expect(preset?.allowed).toContain("repo_change");
    expect(preset?.allowed).not.toContain("protected_branch_merge");
    expect(preset?.allowed).not.toContain("production_deployment");
  });

  it("ships a regulated AI PR gate preset that gates release actions and blocks data/admin", () => {
    const preset = AGENT_CONTROL_PRESETS.find((candidate) => candidate.id === "regulated_ai_pr_gate");
    expect(preset).toBeDefined();

    const { allowed_actions, blocked_actions } = buildActionPolicyLists(
      [],
      [],
      preset?.allowed ?? [],
    );

    // Release actions are allowed so the backend gates them on trust (>=80).
    expect(allowed_actions).toEqual(
      expect.arrayContaining([
        "repo_change",
        "ci_workflow_change",
        "protected_branch_merge",
        "production_deployment",
      ]),
    );
    // Sensitive runtime actions hard-block.
    expect(blocked_actions).toContain("data_export");
    expect(blocked_actions).toContain("admin_action");
    expect(blocked_actions).toContain("financial_transaction");
  });
});
