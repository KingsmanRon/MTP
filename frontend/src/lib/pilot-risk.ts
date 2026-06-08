export type PilotRiskSignalId =
  | "external_tools"
  | "sensitive_data"
  | "production_changes"
  | "financial_actions"
  | "external_communications"
  | "authorization_gap"
  | "tamper_evidence_gap"
  | "security_review_blocked";

export interface PilotRiskSignal {
  id: PilotRiskSignalId;
  question: string;
  detail: string;
  weight: number;
}

export interface PilotRiskAssessment {
  score: number;
  maxScore: number;
  level: "observe" | "candidate" | "priority";
  label: string;
  summary: string;
  recommendedWorkflow: string;
  selectedSignals: string[];
}

export const PILOT_RISK_SIGNALS: PilotRiskSignal[] = [
  {
    id: "external_tools",
    question: "Do your agents call external tools or APIs?",
    detail: "Creates execution risk outside the model boundary.",
    weight: 1,
  },
  {
    id: "sensitive_data",
    question: "Can agents access or export sensitive customer data?",
    detail: "Creates privacy, access-control, and incident-response exposure.",
    weight: 2,
  },
  {
    id: "production_changes",
    question: "Can agents change production code or infrastructure?",
    detail: "Creates operational and change-control risk.",
    weight: 2,
  },
  {
    id: "financial_actions",
    question: "Can agents trigger payments, refunds, or spend?",
    detail: "Creates direct financial loss and authorization risk.",
    weight: 3,
  },
  {
    id: "external_communications",
    question: "Can agents message customers, partners, or employees?",
    detail: "Creates reputational and communication-policy risk.",
    weight: 1,
  },
  {
    id: "authorization_gap",
    question: "Would you struggle to prove who authorized an action?",
    detail: "Signals an accountability and governance gap.",
    weight: 2,
  },
  {
    id: "tamper_evidence_gap",
    question: "Would you struggle to prove the logs were not changed?",
    detail: "Signals an audit-evidence and repudiation gap.",
    weight: 2,
  },
  {
    id: "security_review_blocked",
    question: "Is a security review slowing or blocking production rollout?",
    detail: "Signals an active, budgeted deployment problem.",
    weight: 3,
  },
];

const MAX_SCORE = PILOT_RISK_SIGNALS.reduce((total, signal) => total + signal.weight, 0);

function recommendWorkflow(selected: Set<PilotRiskSignalId>): string {
  if (selected.has("financial_actions")) {
    return "Agent spend and payment authorization";
  }
  if (selected.has("production_changes")) {
    return "Production change control";
  }
  if (selected.has("sensitive_data")) {
    return "Sensitive data access and export";
  }
  if (selected.has("external_tools")) {
    return "External tool execution";
  }
  if (selected.has("external_communications")) {
    return "Customer-facing agent actions";
  }
  return "Highest-risk action discovery";
}

export function assessPilotRisk(selectedIds: PilotRiskSignalId[]): PilotRiskAssessment {
  const selected = new Set(selectedIds);
  const score = PILOT_RISK_SIGNALS.reduce(
    (total, signal) => total + (selected.has(signal.id) ? signal.weight : 0),
    0,
  );

  const selectedSignals = PILOT_RISK_SIGNALS.filter((signal) => selected.has(signal.id)).map(
    (signal) => signal.question,
  );

  if (score >= 8) {
    return {
      score,
      maxScore: MAX_SCORE,
      level: "priority",
      label: "Priority pilot candidate",
      summary:
        "Your agents combine meaningful execution rights with an active authorization or evidence gap.",
      recommendedWorkflow: recommendWorkflow(selected),
      selectedSignals,
    };
  }

  if (score >= 4) {
    return {
      score,
      maxScore: MAX_SCORE,
      level: "candidate",
      label: "Pilot candidate",
      summary:
        "You have a concrete high-risk workflow worth instrumenting before agent autonomy expands.",
      recommendedWorkflow: recommendWorkflow(selected),
      selectedSignals,
    };
  }

  return {
    score,
    maxScore: MAX_SCORE,
    level: "observe",
    label: "Early-stage risk",
    summary:
      "Your current exposure appears limited. Identify the first action that will need production credentials or approval.",
    recommendedWorkflow: recommendWorkflow(selected),
    selectedSignals,
  };
}
