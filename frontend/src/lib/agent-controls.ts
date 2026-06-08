export const CONTROLLED_ACTIONS = [
  {
    id: "financial_transaction",
    label: "Financial transactions",
    description: "Payments, refunds, purchases, and agent-triggered spend.",
    group: "runtime",
  },
  {
    id: "tool_call",
    label: "Tool execution",
    description: "Calls to MCP tools and other agent execution adapters.",
    group: "runtime",
  },
  {
    id: "api_call",
    label: "External API calls",
    description: "Requests that cause effects in external systems.",
    group: "runtime",
  },
  {
    id: "data_export",
    label: "Sensitive data export",
    description: "Exports or transfers of datasets and customer information.",
    group: "runtime",
  },
  {
    id: "email_send",
    label: "External communications",
    description: "Emails and outbound messages sent by the agent.",
    group: "runtime",
  },
  {
    id: "admin_action",
    label: "Administrative actions",
    description: "Privileged configuration and account operations.",
    group: "runtime",
  },
  {
    id: "repo_change",
    label: "Repository changes",
    description: "Commits and pull-request changes recorded before review.",
    group: "code_release",
  },
  {
    id: "ci_workflow_change",
    label: "CI/CD workflow changes",
    description: "Changes to build, security, and deployment automation.",
    group: "code_release",
  },
  {
    id: "protected_branch_merge",
    label: "Protected branch merges",
    description: "Merges into the repository's configured production branch.",
    group: "code_release",
  },
  {
    id: "production_deployment",
    label: "Production deployments",
    description: "Releases or deployments that change the live environment.",
    group: "code_release",
  },
] as const;

export type ControlledActionId = (typeof CONTROLLED_ACTIONS)[number]["id"];
export type ControlledActionGroupId = (typeof CONTROLLED_ACTIONS)[number]["group"];

export const CONTROLLED_ACTION_GROUPS: Array<{
  id: ControlledActionGroupId;
  label: string;
  description: string;
}> = [
  {
    id: "runtime",
    label: "Runtime actions",
    description: "Actions an agent performs against tools, systems, money, and data.",
  },
  {
    id: "code_release",
    label: "Code and release",
    description:
      "Use these with required repository or deployment checks so an Inntris BLOCK is enforced.",
  },
];

export interface AgentControlPreset {
  id: string;
  label: string;
  description: string;
  dailyLimit: number;
  perActionLimit: number;
  rateLimit: number;
  allowed: ControlledActionId[];
}

export const AGENT_CONTROL_PRESETS: AgentControlPreset[] = [
  {
    id: "spend_guard",
    label: "Spend guard",
    description: "Allow bounded spend and supporting tool/API calls.",
    dailyLimit: 1000,
    perActionLimit: 100,
    rateLimit: 30,
    allowed: ["financial_transaction", "tool_call", "api_call"],
  },
  {
    id: "tool_execution",
    label: "Tool execution",
    description: "Allow tools and APIs while blocking money, data exports, and admin actions.",
    dailyLimit: 0,
    perActionLimit: 0,
    rateLimit: 60,
    allowed: ["tool_call", "api_call"],
  },
  {
    id: "data_export",
    label: "Data export",
    description: "Allow controlled data export plus supporting tool/API calls.",
    dailyLimit: 0,
    perActionLimit: 0,
    rateLimit: 10,
    allowed: ["data_export", "tool_call", "api_call"],
  },
  {
    id: "code_release_guard",
    label: "Code & release guard",
    description: "Allow code proposals while blocking protected merges, workflow changes, and deploys.",
    dailyLimit: 0,
    perActionLimit: 0,
    rateLimit: 30,
    allowed: ["repo_change", "tool_call", "api_call"],
  },
  {
    id: "lockdown",
    label: "Lock down",
    description: "Block every standard high-risk action while the agent remains online.",
    dailyLimit: 0,
    perActionLimit: 0,
    rateLimit: 1,
    allowed: [],
  },
];

export function buildActionPolicyLists(
  existingAllowed: string[] = [],
  existingBlocked: string[] = [],
  allowedControlledActions: Iterable<string>,
): { allowed_actions: string[]; blocked_actions: string[] } {
  const controlled = new Set<string>(CONTROLLED_ACTIONS.map((action) => action.id));
  const selectedAllowed = new Set<string>(allowedControlledActions);
  const customAllowed = existingAllowed.filter((action) => !controlled.has(action));
  const customBlocked = existingBlocked.filter(
    (action) => !controlled.has(action) && !customAllowed.includes(action),
  );

  return {
    allowed_actions: [
      ...customAllowed,
      ...CONTROLLED_ACTIONS.filter((action) => selectedAllowed.has(action.id)).map(
        (action) => action.id,
      ),
    ],
    blocked_actions: [
      ...customBlocked,
      ...CONTROLLED_ACTIONS.filter((action) => !selectedAllowed.has(action.id)).map(
        (action) => action.id,
      ),
    ],
  };
}
