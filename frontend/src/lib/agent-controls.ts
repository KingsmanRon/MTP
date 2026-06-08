export const CONTROLLED_ACTIONS = [
  {
    id: "financial_transaction",
    label: "Financial transactions",
    description: "Payments, refunds, purchases, and agent-triggered spend.",
  },
  {
    id: "tool_call",
    label: "Tool execution",
    description: "Calls to MCP tools and other agent execution adapters.",
  },
  {
    id: "api_call",
    label: "External API calls",
    description: "Requests that cause effects in external systems.",
  },
  {
    id: "data_export",
    label: "Sensitive data export",
    description: "Exports or transfers of datasets and customer information.",
  },
  {
    id: "email_send",
    label: "External communications",
    description: "Emails and outbound messages sent by the agent.",
  },
  {
    id: "admin_action",
    label: "Administrative actions",
    description: "Privileged configuration and account operations.",
  },
] as const;

export type ControlledActionId = (typeof CONTROLLED_ACTIONS)[number]["id"];

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
