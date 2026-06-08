import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AgentControlPanel } from "../agent-control-panel";
import type { MappedAgent } from "@/lib/admin/types";

const agent: MappedAgent = {
  id: "agent-123",
  name: "Payment Agent",
  status: "active",
  daily_limit_usd: 500,
  per_action_limit_usd: 50,
  rate_limit_per_minute: 60,
  allowed_actions: ["promptfoo_eval", "api_call"],
  blocked_actions: ["repo_change", "admin_action"],
};

describe("AgentControlPanel", () => {
  afterEach(() => {
    delete (globalThis as unknown as { fetch?: unknown }).fetch;
  });

  it("stages the spend preset and saves enforceable controls", async () => {
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => agent,
    });
    (globalThis as unknown as { fetch: typeof fetchMock }).fetch = fetchMock;
    const onSaved = jest.fn();

    render(<AgentControlPanel agent={agent} onSaved={onSaved} />);

    fireEvent.click(screen.getByText("Spend guard"));

    expect(screen.getByLabelText("Daily spend limit")).toHaveValue(1000);
    expect(screen.getByLabelText("Per-action spend limit")).toHaveValue(100);
    expect(screen.getByLabelText("Rate limit")).toHaveValue(30);
    expect(screen.getByLabelText("Financial transactions decision")).toHaveValue("allow");
    expect(screen.getByLabelText("Administrative actions decision")).toHaveValue("block");

    fireEvent.click(screen.getByRole("button", { name: "Save controls" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const [, request] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(String(request?.body));

    expect(body.allowed_actions).toEqual([
      "promptfoo_eval",
      "financial_transaction",
      "tool_call",
      "api_call",
    ]);
    expect(body.blocked_actions).toContain("repo_change");
    expect(body.blocked_actions).toContain("admin_action");
    expect(body.daily_limit_usd).toBe(1000);
    expect(body.per_action_limit_usd).toBe(100);
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
  });
});
