/**
 * Casefile — offensive security case tracker for pi.
 *
 * Tools: CaseAdd, CaseUpdate, CaseGet, CaseList, CaseSearch, CaseLink, CaseUnlink
 * Command: /casefile — interactive dashboard
 * Event: before_agent_start — injects case summary context into the system prompt
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { StringEnum } from "@earendil-works/pi-ai";
import { Type } from "typebox";
import { Text, matchesKey, truncateToWidth } from "@earendil-works/pi-tui";

import {
  type CaseRecord,
  type CaseStatus,
  type CaseConfidence,
  type CaseSeverity,
  type CasePriority,
  addCase,
  updateCase,
  deleteCase,
  searchCases,
  countCases,
  linkCases,
  unlinkCases,
  formatCase,
  formatCases,
  formatCaseDetail,
  getCasefilePath,
  readCasefile,
} from "./ledger.js";

// ── Schemas ───────────────────────────────────────────────────────────

const CaseStatusSchema = StringEnum([
  "hypothesis",
  "investigating",
  "confirmed",
  "blocked",
  "killed",
  "reported",
] as const satisfies CaseStatus[]);

const CaseConfidenceSchema = StringEnum([
  "low",
  "medium",
  "high",
] as const satisfies CaseConfidence[]);

const CaseSeveritySchema = StringEnum([
  "info",
  "low",
  "medium",
  "high",
  "critical",
] as const satisfies CaseSeverity[]);

const CasePrioritySchema = StringEnum([
  "P0",
  "P1",
  "P2",
  "P3",
  "P4",
] as const satisfies CasePriority[]);

const CommonFields = {
  status: Type.Optional(CaseStatusSchema),
  confidence: Type.Optional(CaseConfidenceSchema),
  severity: Type.Optional(CaseSeveritySchema),
  priority: Type.Optional(CasePrioritySchema),
  target: Type.Optional(Type.String({ description: "Target asset, host, repo, or scope" })),
  endpoint: Type.Optional(Type.String({ description: "Endpoint, route, file, or object" })),
  bug_class: Type.Optional(Type.String({ description: "Bug class or root cause category" })),
  evidence: Type.Optional(Type.String({ description: "Observed evidence or repro notes" })),
  impact: Type.Optional(Type.String({ description: "Security impact or chain value" })),
  next_step: Type.Optional(Type.String({ description: "Next validation or exploit step" })),
  poc: Type.Optional(Type.String({ description: "Proof of concept steps" })),
  remediation: Type.Optional(Type.String({ description: "How to fix it" })),
  references: Type.Optional(Type.Array(Type.String(), { description: "External URLs, CVEs" })),
  blockers: Type.Optional(Type.Array(Type.String(), { description: "Current blockers" })),
  tags: Type.Optional(Type.Array(Type.String(), { description: "Tags for filtering" })),
  linked_case_ids: Type.Optional(Type.Array(Type.String(), { description: "Related case IDs" })),
};

// ── Tool: CaseAdd ─────────────────────────────────────────────────────

const AddSchema = Type.Object(
  {
    title: Type.String({ description: "Short case title" }),
    ...CommonFields,
  },
  { additionalProperties: false },
);

// ── Tool: CaseUpdate ──────────────────────────────────────────────────

const UpdateSchema = Type.Object(
  {
    id: Type.String({ description: "Case ID to update" }),
    title: Type.Optional(Type.String()),
    ...CommonFields,
  },
  { additionalProperties: false },
);

// ── Tool: CaseGet ─────────────────────────────────────────────────────

const GetSchema = Type.Object(
  {
    id: Type.String({ description: "Case ID" }),
  },
  { additionalProperties: false },
);

// ── Tool: CaseList ────────────────────────────────────────────────────

const ListSchema = Type.Object(
  {
    status: Type.Optional(CaseStatusSchema),
    confidence: Type.Optional(CaseConfidenceSchema),
    severity: Type.Optional(CaseSeveritySchema),
    priority: Type.Optional(CasePrioritySchema),
    tag: Type.Optional(Type.String({ description: "Filter by tag" })),
    limit: Type.Optional(Type.Number({ description: "Max results (default 50)" })),
    offset: Type.Optional(Type.Number({ description: "Skip N results for pagination" })),
  },
  { additionalProperties: false },
);

// ── Tool: CaseSearch ──────────────────────────────────────────────────

const SearchSchema = Type.Object(
  {
    query: Type.String({ description: "Text to search across cases" }),
    field: Type.Optional(
      StringEnum(["title", "evidence", "impact", "target", "endpoint", "bugClass"] as const, {
        description: "Restrict search to a specific field",
      }),
    ),
    status: Type.Optional(CaseStatusSchema),
    confidence: Type.Optional(CaseConfidenceSchema),
    severity: Type.Optional(CaseSeveritySchema),
    tag: Type.Optional(Type.String()),
    limit: Type.Optional(Type.Number()),
    offset: Type.Optional(Type.Number()),
  },
  { additionalProperties: false },
);

// ── Tool: CaseLink ────────────────────────────────────────────────────

const LinkSchema = Type.Object(
  {
    source_id: Type.String({ description: "First case ID" }),
    target_id: Type.String({ description: "Second case ID to link" }),
  },
  { additionalProperties: false },
);

// ── Tool: CaseUnlink ──────────────────────────────────────────────────

const UnlinkSchema = Type.Object(
  {
    source_id: Type.String({ description: "First case ID" }),
    target_id: Type.String({ description: "Second case ID to unlink" }),
  },
  { additionalProperties: false },
);

// ── Rendering helpers ────────────────────────────────────────────────

const STATUS_COLORS: Record<string, string> = {
  hypothesis: "dim",
  investigating: "warning",
  confirmed: "success",
  blocked: "error",
  killed: "dim",
  reported: "accent",
};

const CONFIDENCE_COLORS: Record<string, string> = {
  low: "dim",
  medium: "warning",
  high: "success",
};

function renderOneLine(record: CaseRecord, theme: any): string {
  const statusColor = STATUS_COLORS[record.status] ?? "muted";
  const confColor = CONFIDENCE_COLORS[record.confidence] ?? "muted";
  let line = theme.fg(statusColor, record.status) + "/" + theme.fg(confColor, record.confidence);
  line += " " + theme.bold(record.title);
  if (record.severity) line += " " + theme.fg("error", `[${record.severity}]`);
  if (record.priority) line += " " + theme.fg("accent", `[${record.priority}]`);
  if (record.bugClass) line += " " + theme.fg("muted", `(${record.bugClass})`);
  return line;
}

// ── Dashboard component ──────────────────────────────────────────────

class CasefileDashboard {
  private records: CaseRecord[];
  private theme: any;
  private onClose: () => void;
  private cachedWidth?: number;
  private cachedLines?: string[];

  constructor(records: CaseRecord[], theme: any, onClose: () => void) {
    this.records = records;
    this.theme = theme;
    this.onClose = onClose;
  }

  handleInput(data: string): void {
    if (matchesKey(data, "escape") || matchesKey(data, "ctrl+c")) {
      this.onClose();
    }
  }

  render(width: number): string[] {
    if (this.cachedLines && this.cachedWidth === width) {
      return this.cachedLines;
    }
    const th = this.theme;
    const lines: string[] = [];
    const title = th.fg("accent", ` Casefile (${this.records.length}) `);
    const headerLine =
      th.fg("borderMuted", "─".repeat(3)) +
      title +
      th.fg("borderMuted", "─".repeat(Math.max(0, width - this.records.length.toString().length - 16)));
    lines.push("");
    lines.push(truncateToWidth(headerLine, width));

    if (this.records.length === 0) {
      lines.push("");
      lines.push(truncateToWidth(`  ${th.fg("dim", "No cases yet. Ask the agent to track findings!")}`, width));
    } else {
      lines.push("");
      for (const r of this.records) {
        lines.push(truncateToWidth(`  ${th.fg("dim", r.id)} ${renderOneLine(r, th)}`, width));
      }
    }

    lines.push("");
    lines.push(truncateToWidth(`  ${th.fg("dim", "Press Escape to close")}`, width));
    lines.push("");

    this.cachedWidth = width;
    this.cachedLines = lines;
    return lines;
  }

  invalidate(): void {
    this.cachedWidth = undefined;
    this.cachedLines = undefined;
  }
}

// ── Context injection ─────────────────────────────────────────────────

function buildCaseContext(records: CaseRecord[]): string {
  if (records.length === 0) return "";

  const confirmed = records.filter((r) => r.status === "confirmed");
  const investigating = records.filter((r) => r.status === "investigating");
  const hypothesis = records.filter((r) => r.status === "hypothesis");
  const blocked = records.filter((r) => r.status === "blocked");

  const lines: string[] = [
    "<casefile_context>",
    `Active cases: ${records.length} total (${confirmed.length} confirmed, ${investigating.length} investigating, ${hypothesis.length} hypothesis, ${blocked.length} blocked)`,
  ];

  if (confirmed.length > 0) {
    lines.push("  Confirmed cases:");
    for (const c of confirmed) {
      lines.push(`  - ${c.id}: ${c.title} [${c.severity ?? "?"}]${c.nextStep ? ` → ${c.nextStep}` : ""}`);
    }
  }

  if (investigating.length > 0) {
    lines.push("  Under investigation:");
    for (const c of investigating) {
      lines.push(`  - ${c.id}: ${c.title}${c.nextStep ? ` → ${c.nextStep}` : ""}`);
    }
  }

  const highPrio = records.filter(
    (r) => r.priority === "P0" || r.priority === "P1",
  );
  if (highPrio.length > 0) {
    lines.push("  High priority:");
    for (const c of highPrio) {
      lines.push(`  - ${c.id}: ${c.title} [${c.priority}]`);
    }
  }

  lines.push("</casefile_context>");
  return lines.join("\n");
}

// ── Main extension ────────────────────────────────────────────────────

export default function casefileExtension(pi: ExtensionAPI) {
  // ── Tool: CaseAdd ──

  pi.registerTool({
    name: "CaseAdd",
    label: "Add Case",
    description:
      "Open a new case in the casefile ledger. Track security hypotheses, evidence points, confirmed vulnerabilities, blockers, and exploit chain steps during bug bounties, CTFs, and security audits.",
    promptSnippet: "Record a security finding or hypothesis as a case",
    promptGuidelines: [
      "Use CaseAdd when you discover or hypothesize a security issue. Even unconfirmed observations should be recorded as hypothesis status — promote them later with CaseUpdate.",
      "Set status='hypothesis' for unconfirmed observations, 'investigating' when actively testing, 'confirmed' when you have proof, and 'reported' when filed.",
      "Always record evidence in the evidence field, impact in the impact field, and next steps in the next_step field. These are critical for chain construction.",
    ],
    parameters: AddSchema,

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const record = await addCase({
        title: params.title,
        status: params.status,
        confidence: params.confidence,
        severity: params.severity,
        priority: params.priority,
        target: params.target,
        endpoint: params.endpoint,
        bugClass: params.bug_class,
        evidence: params.evidence,
        impact: params.impact,
        nextStep: params.next_step,
        poc: params.poc,
        remediation: params.remediation,
        references: params.references,
        blockers: params.blockers,
        tags: params.tags,
        linkedCaseIds: params.linked_case_ids,
      });
      return {
        content: [
          {
            type: "text",
            text: `Case opened:\n${formatCaseDetail(record)}\n\nLedger: ${getCasefilePath()}`,
          },
        ],
        details: { record, ledger_path: getCasefilePath() },
      };
    },

    renderCall(args, theme) {
      return new Text(
        theme.fg("toolTitle", theme.bold("CaseAdd ")) + theme.fg("muted", args.title),
        0,
        0,
      );
    },

    renderResult(result, { expanded }, theme) {
      const details = result.details as { record?: CaseRecord } | undefined;
      if (!details?.record) {
        const text = result.content[0];
        return new Text(text?.type === "text" ? text.text : "Opened", 0, 0);
      }
      const c = details.record;
      let line = theme.fg("success", "✓ ") + renderOneLine(c, theme);
      if (expanded) {
        line += "\n" + theme.fg("dim", `  ${c.id} → ${c.nextStep ?? "no next step"}`);
      }
      return new Text(line, 0, 0);
    },
  });

  // ── Tool: CaseUpdate ──

  pi.registerTool({
    name: "CaseUpdate",
    label: "Update Case",
    description:
      "Update an existing case. Change status, add evidence, update confidence, set severity, record next steps.",
    promptSnippet: "Update a security case with new evidence or status",
    promptGuidelines: [
      "Use CaseUpdate when new evidence, status changes, confidence updates, or blockers change for an existing case.",
      "Promote from 'hypothesis' → 'investigating' when you start actively testing, 'investigating' → 'confirmed' when you have proof.",
    ],
    parameters: UpdateSchema,

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const record = await updateCase(params.id, {
        title: params.title,
        status: params.status,
        confidence: params.confidence,
        severity: params.severity,
        priority: params.priority,
        target: params.target,
        endpoint: params.endpoint,
        bugClass: params.bug_class,
        evidence: params.evidence,
        impact: params.impact,
        nextStep: params.next_step,
        poc: params.poc,
        remediation: params.remediation,
        references: params.references,
        blockers: params.blockers,
        tags: params.tags,
        linkedCaseIds: params.linked_case_ids,
      });
      return {
        content: [
          {
            type: "text",
            text: `Case updated:\n${formatCaseDetail(record)}`,
          },
        ],
        details: { record },
      };
    },

    renderCall(args, theme) {
      return new Text(
        theme.fg("toolTitle", theme.bold("CaseUpdate ")) + theme.fg("dim", args.id),
        0,
        0,
      );
    },

    renderResult(result, { expanded }, theme) {
      const details = result.details as { record?: CaseRecord } | undefined;
      if (!details?.record) {
        const text = result.content[0];
        return new Text(text?.type === "text" ? text.text : "Updated", 0, 0);
      }
      const c = details.record;
      let line = theme.fg("success", "✓ ") + renderOneLine(c, theme);
      if (expanded) {
        line += "\n" + theme.fg("dim", `  ${c.id} [${c.status}/${c.confidence}]`);
      }
      return new Text(line, 0, 0);
    },
  });

  // ── Tool: CaseGet ──

  pi.registerTool({
    name: "CaseGet",
    label: "Get Case",
    description: "Get full details of a single case by ID.",
    promptSnippet: "Look up a specific case by ID",
    parameters: GetSchema,

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const records = await readCasefile();
      const record = records.find((r) => r.id === params.id);
      if (!record) {
        throw new Error(`Case not found: ${params.id}`);
      }
      return {
        content: [{ type: "text", text: formatCaseDetail(record) }],
        details: { record },
      };
    },

    isReadOnly() {
      return true;
    },

    renderCall(args, theme) {
      return new Text(
        theme.fg("toolTitle", theme.bold("CaseGet ")) + theme.fg("dim", args.id),
        0,
        0,
      );
    },

    renderResult(result, _options, theme) {
      const details = result.details as { record?: CaseRecord } | undefined;
      if (!details?.record) {
        const text = result.content[0];
        return new Text(text?.type === "text" ? text.text : "", 0, 0);
      }
      return new Text(renderOneLine(details.record, theme), 0, 0);
    },
  });

  // ── Tool: CaseList ──

  pi.registerTool({
    name: "CaseList",
    label: "List Cases",
    description:
      "List cases from the casefile with optional filters. Returns paginated results with total count.",
    promptSnippet: "List or filter security cases",
    promptGuidelines: [
      "Use CaseList before opening new cases to check for duplicates and review the current state of all cases.",
    ],
    parameters: ListSchema,

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const { cases, total } = await searchCases({
        status: params.status as CaseStatus | undefined,
        confidence: params.confidence as CaseConfidence | undefined,
        severity: params.severity as CaseSeverity | undefined,
        priority: params.priority as CasePriority | undefined,
        tag: params.tag,
        limit: params.limit,
        offset: params.offset,
      });
      const offset = params.offset ?? 0;
      const header = `Showing ${cases.length} of ${total} cases (offset: ${offset})`;
      const body = cases.length > 0 ? formatCases(cases) : "No cases match filters.";
      return {
        content: [{ type: "text", text: `${header}\n${body}` }],
        details: { cases, total, offset },
      };
    },

    isReadOnly() {
      return true;
    },

    renderCall(_args, theme) {
      return new Text(theme.fg("toolTitle", theme.bold("CaseList")), 0, 0);
    },

    renderResult(result, { expanded }, theme) {
      const details = result.details as
        | { cases?: CaseRecord[]; total?: number }
        | undefined;
      const total = details?.total ?? 0;
      const cases = details?.cases ?? [];
      let line = theme.fg("success", "✓ ") + theme.fg("muted", `${total} case(s)`);
      if (expanded && cases.length > 0) {
        line += "\n" + cases.map((c) => "  " + renderOneLine(c, theme)).join("\n");
      }
      return new Text(line, 0, 0);
    },
  });

  // ── Tool: CaseSearch ──

  pi.registerTool({
    name: "CaseSearch",
    label: "Search Cases",
    description:
      "Full-text search across cases. Optionally restrict to a specific field (title, evidence, impact, target, endpoint, bugClass). Returns paginated results with total count.",
    promptSnippet: "Search cases by text query, optionally field-scoped",
    parameters: SearchSchema,

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const { cases, total } = await searchCases({
        query: params.query,
        field: params.field as
          | "title"
          | "evidence"
          | "impact"
          | "target"
          | "endpoint"
          | "bugClass"
          | undefined,
        status: params.status as CaseStatus | undefined,
        confidence: params.confidence as CaseConfidence | undefined,
        severity: params.severity as CaseSeverity | undefined,
        tag: params.tag,
        limit: params.limit,
        offset: params.offset,
      });
      const offset = params.offset ?? 0;
      const header = `Search "${params.query}"${params.field ? ` in ${params.field}` : ""}: ${cases.length} of ${total} results (offset: ${offset})`;
      const body = cases.length > 0 ? formatCases(cases) : "No matching cases.";
      return {
        content: [{ type: "text", text: `${header}\n${body}` }],
        details: { cases, total, offset },
      };
    },

    isReadOnly() {
      return true;
    },

    renderCall(args, theme) {
      return new Text(
        theme.fg("toolTitle", theme.bold("CaseSearch ")) +
          theme.fg("dim", `"${args.query}"`),
        0,
        0,
      );
    },

    renderResult(result, { expanded }, theme) {
      const details = result.details as
        | { cases?: CaseRecord[]; total?: number }
        | undefined;
      const total = details?.total ?? 0;
      const cases = details?.cases ?? [];
      let line = theme.fg("success", "✓ ") + theme.fg("muted", `${total} result(s)`);
      if (expanded && cases.length > 0) {
        line += "\n" + cases.map((c) => "  " + renderOneLine(c, theme)).join("\n");
      }
      return new Text(line, 0, 0);
    },
  });

  // ── Tool: CaseLink ──

  pi.registerTool({
    name: "CaseLink",
    label: "Link Cases",
    description:
      "Bidirectionally link two cases. Use to build exploit chains — link a low-impact primitive to a high-impact escalation step.",
    promptSnippet: "Link two cases into an exploit chain",
    parameters: LinkSchema,

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const { source, target } = await linkCases(params.source_id, params.target_id);
      return {
        content: [
          {
            type: "text",
            text: `Linked:\n  ${formatCase(source)}\n  ↔\n  ${formatCase(target)}`,
          },
        ],
        details: { source, target },
      };
    },

    renderCall(args, theme) {
      return new Text(
        theme.fg("toolTitle", theme.bold("CaseLink ")) +
          theme.fg("dim", `${args.source_id} ↔ ${args.target_id}`),
        0,
        0,
      );
    },

    renderResult(result, _options, theme) {
      const details = result.details as
        | { source?: CaseRecord; target?: CaseRecord }
        | undefined;
      if (!details?.source || !details?.target) {
        return new Text("Linked", 0, 0);
      }
      return new Text(
        theme.fg("success", "✓ Linked ") +
          theme.fg("accent", details.source.id) +
          " ↔ " +
          theme.fg("accent", details.target.id),
        0,
        0,
      );
    },
  });

  // ── Tool: CaseUnlink ──

  pi.registerTool({
    name: "CaseUnlink",
    label: "Unlink Cases",
    description: "Remove a bidirectional link between two cases.",
    parameters: UnlinkSchema,

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const { source, target } = await unlinkCases(params.source_id, params.target_id);
      return {
        content: [
          {
            type: "text",
            text: `Unlinked:\n  ${formatCase(source)}\n  ↻\n  ${formatCase(target)}`,
          },
        ],
        details: { source, target },
      };
    },

    renderCall(args, theme) {
      return new Text(
        theme.fg("toolTitle", theme.bold("CaseUnlink ")) +
          theme.fg("dim", `${args.source_id} ↻ ${args.target_id}`),
        0,
        0,
      );
    },

    renderResult(_result, _options, theme) {
      return new Text(theme.fg("success", "✓ Unlinked"), 0, 0);
    },
  });

  // ── Command: /casefile ──

  pi.registerCommand("casefile", {
    description: "Show casefile dashboard with summary stats",
    handler: async (_args, ctx) => {
      if (!ctx.hasUI) {
        const { total, byStatus, bySeverity } = await countCases();
        ctx.ui.notify(
          `Casefile: ${total} total | Status: ${Object.entries(byStatus).map(([k, v]) => `${k}:${v}`).join(", ")} | Severity: ${Object.entries(bySeverity).map(([k, v]) => `${k}:${v}`).join(", ")}`,
          "info",
        );
        return;
      }
      const records = await readCasefile();
      await ctx.ui.custom<void>((_tui, theme, _kb, done) => {
        return new CasefileDashboard(records, theme, () => done());
      });
    },
  });

  // ── Event: Load casefile on session start ──

  pi.on("session_start", async () => {
    try {
      await readCasefile();
    } catch {
      // Casefile might not exist yet
    }
  });

  // ── Event: Inject case context into system prompt ──

  pi.on("before_agent_start", async () => {
    try {
      const records = await readCasefile();
      const active = records.filter((r) => r.status !== "killed" && r.status !== "reported");
      if (active.length === 0) return;

      const caseContext = buildCaseContext(active);
      return {
        message: {
          customType: "casefile_summary",
          content: caseContext,
          display: false,
        },
      };
    } catch {
      // No casefile yet
    }
  });

  // ── Event: Update status bar on case tool results ──

  pi.on("tool_result", async (event, ctx) => {
    const caseTools = ["CaseAdd", "CaseUpdate", "CaseLink", "CaseUnlink"];
    if (
      typeof event.toolName === "string" &&
      caseTools.includes(event.toolName)
    ) {
      const { total } = await countCases();
      ctx.ui.setStatus("casefile", `${total} cases`);
    }
  });
}