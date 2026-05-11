/**
 * Casefile Ledger — storage engine for offensive security cases.
 *
 * - Append-based adds (no full-file rewrite)
 * - Atomic link/unlink operations (single write for both directions)
 * - Dedup on read (append-based updates mean last-write-wins)
 * - Field-scoped search with pagination
 * - Delete with referential cleanup (removes dangling linked IDs)
 */

import { createHash, randomUUID } from "crypto";
import { mkdir, readFile, appendFile, writeFile } from "fs/promises";
import { dirname, join } from "path";
import { homedir } from "os";

// ── Types ────────────────────────────────────────────────────────────

export type CaseStatus =
  | "hypothesis"
  | "investigating"
  | "confirmed"
  | "blocked"
  | "killed"
  | "reported";

export type CaseConfidence = "low" | "medium" | "high";

export type CaseSeverity = "info" | "low" | "medium" | "high" | "critical";

export type CasePriority = "P0" | "P1" | "P2" | "P3" | "P4";

export type CaseRecord = {
  id: string;
  title: string;
  status: CaseStatus;
  confidence: CaseConfidence;
  severity?: CaseSeverity;
  priority?: CasePriority;
  target?: string;
  endpoint?: string;
  bugClass?: string;
  evidence?: string;
  impact?: string;
  nextStep?: string;
  poc?: string;
  remediation?: string;
  references?: string[];
  blockers?: string[];
  tags?: string[];
  linkedCaseIds: string[];
  createdAt: string;
  updatedAt: string;
};

export type CaseInput = {
  title: string;
  status?: CaseStatus;
  confidence?: CaseConfidence;
  severity?: CaseSeverity;
  priority?: CasePriority;
  target?: string;
  endpoint?: string;
  bugClass?: string;
  evidence?: string;
  impact?: string;
  nextStep?: string;
  poc?: string;
  remediation?: string;
  references?: string[];
  blockers?: string[];
  tags?: string[];
  linkedCaseIds?: string[];
};

export type CaseUpdate = Partial<Omit<CaseInput, "linkedCaseIds">> & {
  linkedCaseIds?: string[];
};

export type CaseSearchOptions = {
  query?: string;
  field?: "title" | "evidence" | "impact" | "target" | "endpoint" | "bugClass";
  status?: CaseStatus;
  confidence?: CaseConfidence;
  severity?: CaseSeverity;
  priority?: CasePriority;
  tag?: string;
  limit?: number;
  offset?: number;
};

// ── Constants ────────────────────────────────────────────────────────

const STATUS_ORDER: CaseStatus[] = [
  "hypothesis",
  "investigating",
  "confirmed",
  "blocked",
  "killed",
  "reported",
];

const ALL_TEXT_FIELDS: (keyof CaseRecord)[] = [
  "id",
  "title",
  "status",
  "confidence",
  "severity",
  "priority",
  "target",
  "endpoint",
  "bugClass",
  "evidence",
  "impact",
  "nextStep",
  "poc",
  "remediation",
];

// ── Helpers ──────────────────────────────────────────────────────────

function nowIso(): string {
  return new Date().toISOString();
}

function normalizeList(values: string[] | undefined): string[] {
  return Array.from(
    new Set((values ?? []).map((v) => v.trim()).filter(Boolean)),
  );
}

function normalizeText(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed || undefined;
}

function stableShortId(input: string): string {
  return createHash("sha1").update(input).digest("hex").slice(0, 10);
}

// ── Ledger Path ──────────────────────────────────────────────────────

let ledgerPathOverride: string | undefined;

export function getCasefilePath(): string {
  if (ledgerPathOverride) return ledgerPathOverride;
  return join(homedir(), ".pi", "casefile", "casefile.jsonl");
}

/** For testing only */
export function setCasefilePath(path: string | undefined): void {
  ledgerPathOverride = path;
}

// ── Normalize ─────────────────────────────────────────────────────────

function normalizeCase(
  input: CaseInput,
  existing?: CaseRecord,
): CaseRecord {
  const timestamp = nowIso();
  const title = input.title.trim();
  const id =
    existing?.id ??
    `case_${stableShortId(`${title}\n${timestamp}\n${randomUUID()}`)}`;

  return {
    id,
    title,
    status: input.status ?? existing?.status ?? "hypothesis",
    confidence: input.confidence ?? existing?.confidence ?? "low",
    severity: input.severity ?? existing?.severity,
    priority: input.priority ?? existing?.priority,
    target: normalizeText(input.target) ?? existing?.target,
    endpoint: normalizeText(input.endpoint) ?? existing?.endpoint,
    bugClass: normalizeText(input.bugClass) ?? existing?.bugClass,
    evidence: normalizeText(input.evidence) ?? existing?.evidence,
    impact: normalizeText(input.impact) ?? existing?.impact,
    nextStep: normalizeText(input.nextStep) ?? existing?.nextStep,
    poc: normalizeText(input.poc) ?? existing?.poc,
    remediation: normalizeText(input.remediation) ?? existing?.remediation,
    references: normalizeList(input.references ?? existing?.references),
    blockers: normalizeList(input.blockers ?? existing?.blockers),
    tags: normalizeList(input.tags ?? existing?.tags),
    linkedCaseIds: normalizeList(
      input.linkedCaseIds ?? existing?.linkedCaseIds,
    ).filter((lid) => lid !== id),
    createdAt: existing?.createdAt ?? timestamp,
    updatedAt: timestamp,
  };
}

// ── Read (with dedup — last write wins) ────────────────────────────────

export async function readCasefile(): Promise<CaseRecord[]> {
  try {
    const raw = await readFile(getCasefilePath(), "utf8");
    const records: CaseRecord[] = [];
    const seenIds = new Set<string>();

    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const parsed = JSON.parse(trimmed) as CaseRecord;
        // Deduplicate on read: last write wins (handles appends from updateCase)
        if (seenIds.has(parsed.id)) {
          const dupIndex = records.findIndex((r) => r.id === parsed.id);
          if (dupIndex !== -1) records[dupIndex] = parsed;
        } else {
          seenIds.add(parsed.id);
          records.push(parsed);
        }
      } catch {
        // Skip corrupt lines
      }
    }
    return records;
  } catch {
    return [];
  }
}

// ── Write (full) ─────────────────────────────────────────────────────

async function writeCasefile(records: CaseRecord[]): Promise<void> {
  const ledgerPath = getCasefilePath();
  await mkdir(dirname(ledgerPath), { recursive: true });
  const body = records.map((r) => JSON.stringify(r)).join("\n");
  await writeFile(ledgerPath, body ? `${body}\n` : "", "utf8");
}

// ── Add (append-based) ───────────────────────────────────────────────

export async function addCase(input: CaseInput): Promise<CaseRecord> {
  const record = normalizeCase(input);
  const ledgerPath = getCasefilePath();
  await mkdir(dirname(ledgerPath), { recursive: true });
  await appendFile(ledgerPath, `${JSON.stringify(record)}\n`, "utf8");
  return record;
}

// ── Update (append-based — dedup on read picks up latest) ────────────

export async function updateCase(
  id: string,
  update: CaseUpdate,
): Promise<CaseRecord> {
  const records = await readCasefile();
  const current = records.find((r) => r.id === id);
  if (!current) {
    throw new Error(`Case not found: ${id}`);
  }
  const next = normalizeCase(
    {
      title: update.title ?? current.title,
      status: update.status ?? current.status,
      confidence: update.confidence ?? current.confidence,
      severity: update.severity ?? current.severity,
      priority: update.priority ?? current.priority,
      target: update.target ?? current.target,
      endpoint: update.endpoint ?? current.endpoint,
      bugClass: update.bugClass ?? current.bugClass,
      evidence: update.evidence ?? current.evidence,
      impact: update.impact ?? current.impact,
      nextStep: update.nextStep ?? current.nextStep,
      poc: update.poc ?? current.poc,
      remediation: update.remediation ?? current.remediation,
      references: update.references ?? current.references,
      blockers: update.blockers ?? current.blockers,
      tags: update.tags ?? current.tags,
      linkedCaseIds: update.linkedCaseIds ?? current.linkedCaseIds,
    },
    current,
  );
  // Append updated record — dedup on read picks up the latest version
  const ledgerPath = getCasefilePath();
  await mkdir(dirname(ledgerPath), { recursive: true });
  await appendFile(ledgerPath, `${JSON.stringify(next)}\n`, "utf8");
  return next;
}

// ── Delete (full rewrite — removes record + cleans dangling refs) ────

export async function deleteCase(id: string): Promise<CaseRecord> {
  const records = await readCasefile();
  const index = records.findIndex((r) => r.id === id);
  if (index === -1) {
    throw new Error(`Case not found: ${id}`);
  }
  const [removed] = records.splice(index, 1);
  for (const record of records) {
    if (record.linkedCaseIds.includes(id)) {
      record.linkedCaseIds = record.linkedCaseIds.filter((lid) => lid !== id);
    }
  }
  await writeCasefile(records);
  return removed;
}

// ── Link (atomic: single write for both directions) ──────────────────

export async function linkCases(
  sourceId: string,
  targetId: string,
): Promise<{ source: CaseRecord; target: CaseRecord }> {
  if (sourceId === targetId) {
    throw new Error("Cannot link a case to itself");
  }
  const records = await readCasefile();
  const source = records.find((r) => r.id === sourceId);
  const target = records.find((r) => r.id === targetId);
  if (!source) throw new Error(`Case not found: ${sourceId}`);
  if (!target) throw new Error(`Case not found: ${targetId}`);

  if (!source.linkedCaseIds.includes(targetId)) {
    source.linkedCaseIds = [...source.linkedCaseIds, targetId];
  }
  if (!target.linkedCaseIds.includes(sourceId)) {
    target.linkedCaseIds = [...target.linkedCaseIds, sourceId];
  }
  const now = nowIso();
  source.updatedAt = now;
  target.updatedAt = now;

  await writeCasefile(records);
  return { source, target };
}

// ── Unlink (atomic: single write) ────────────────────────────────────

export async function unlinkCases(
  sourceId: string,
  targetId: string,
): Promise<{ source: CaseRecord; target: CaseRecord }> {
  const records = await readCasefile();
  const source = records.find((r) => r.id === sourceId);
  const target = records.find((r) => r.id === targetId);
  if (!source) throw new Error(`Case not found: ${sourceId}`);
  if (!target) throw new Error(`Case not found: ${targetId}`);

  const now = nowIso();
  source.linkedCaseIds = source.linkedCaseIds.filter((lid) => lid !== targetId);
  target.linkedCaseIds = target.linkedCaseIds.filter((lid) => lid !== sourceId);
  source.updatedAt = now;
  target.updatedAt = now;

  await writeCasefile(records);
  return { source, target };
}

// ── Search (field-scoped) ────────────────────────────────────────────

function caseHaystack(
  record: CaseRecord,
  field?: CaseSearchOptions["field"],
): string {
  if (field) {
    const val = record[field];
    if (Array.isArray(val)) return val.join(" ").toLowerCase();
    return (typeof val === "string" ? val : String(val ?? "")).toLowerCase();
  }
  const parts: string[] = [];
  for (const key of ALL_TEXT_FIELDS) {
    const val = record[key];
    if (Array.isArray(val)) parts.push((val as string[]).join(" "));
    else if (typeof val === "string") parts.push(val);
  }
  parts.push(...(record.blockers ?? []));
  parts.push(...(record.tags ?? []));
  parts.push(...(record.references ?? []));
  parts.push(...(record.linkedCaseIds ?? []));
  return parts.filter(Boolean).join("\n").toLowerCase();
}

export async function searchCases(
  options: CaseSearchOptions = {},
): Promise<{ cases: CaseRecord[]; total: number }> {
  const query = options.query?.trim().toLowerCase();
  const field = options.field;
  const tag = options.tag?.trim().toLowerCase();
  const limit = Math.max(1, Math.min(options.limit ?? 50, 200));
  const offset = Math.max(0, options.offset ?? 0);

  const filtered = (await readCasefile())
    .filter((r) => !options.status || r.status === options.status)
    .filter((r) => !options.confidence || r.confidence === options.confidence)
    .filter((r) => !options.severity || r.severity === options.severity)
    .filter((r) => !options.priority || r.priority === options.priority)
    .filter(
      (r) => !tag || r.tags?.some((t) => t.toLowerCase() === tag),
    )
    .filter((r) => !query || caseHaystack(r, field).includes(query))
    .sort((a, b) => {
      const aStatus = STATUS_ORDER.indexOf(a.status);
      const bStatus = STATUS_ORDER.indexOf(b.status);
      if (aStatus !== bStatus) return aStatus - bStatus;
      return b.updatedAt.localeCompare(a.updatedAt);
    });

  return {
    total: filtered.length,
    cases: filtered.slice(offset, offset + limit),
  };
}

// ── Count ─────────────────────────────────────────────────────────────

export async function countCases(): Promise<{
  total: number;
  byStatus: Record<string, number>;
  bySeverity: Record<string, number>;
}> {
  const records = await readCasefile();
  const byStatus: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  for (const r of records) {
    byStatus[r.status] = (byStatus[r.status] ?? 0) + 1;
    if (r.severity) bySeverity[r.severity] = (bySeverity[r.severity] ?? 0) + 1;
  }
  return { total: records.length, byStatus, bySeverity };
}

// ── Format ────────────────────────────────────────────────────────────

export function formatCase(record: CaseRecord): string {
  const bits = [
    `${record.id} [${record.status}/${record.confidence}] ${record.title}`,
    record.priority ? `priority=${record.priority}` : undefined,
    record.severity ? `severity=${record.severity}` : undefined,
    record.bugClass ? `class=${record.bugClass}` : undefined,
    record.endpoint ? `endpoint=${record.endpoint}` : undefined,
    record.target ? `target=${record.target}` : undefined,
    record.tags?.length ? `tags=${record.tags.join(",")}` : undefined,
    record.linkedCaseIds.length
      ? `links=${record.linkedCaseIds.join(",")}`
      : undefined,
    record.nextStep ? `next=${record.nextStep}` : undefined,
  ].filter(Boolean);
  return bits.join(" | ");
}

export function formatCases(records: CaseRecord[]): string {
  if (records.length === 0) return "No cases recorded.";
  return records.map(formatCase).join("\n");
}

export function formatCaseDetail(record: CaseRecord): string {
  const lines = [
    `═══ ${record.id} ═══`,
    `Title:       ${record.title}`,
    `Status:      ${record.status}`,
    `Confidence:  ${record.confidence}`,
  ];
  if (record.severity) lines.push(`Severity:    ${record.severity}`);
  if (record.priority) lines.push(`Priority:    ${record.priority}`);
  if (record.target) lines.push(`Target:      ${record.target}`);
  if (record.endpoint) lines.push(`Endpoint:    ${record.endpoint}`);
  if (record.bugClass) lines.push(`Bug class:   ${record.bugClass}`);
  if (record.evidence) lines.push(`Evidence:    ${record.evidence}`);
  if (record.impact) lines.push(`Impact:      ${record.impact}`);
  if (record.poc) lines.push(`PoC:         ${record.poc}`);
  if (record.remediation) lines.push(`Remediation: ${record.remediation}`);
  if (record.nextStep) lines.push(`Next step:   ${record.nextStep}`);
  if (record.references?.length)
    lines.push(`References:  ${record.references.join(", ")}`);
  if (record.blockers?.length)
    lines.push(`Blockers:    ${record.blockers.join(", ")}`);
  if (record.tags?.length) lines.push(`Tags:        ${record.tags.join(", ")}`);
  if (record.linkedCaseIds.length)
    lines.push(`Linked:      ${record.linkedCaseIds.join(", ")}`);
  lines.push(`Created:     ${record.createdAt}`);
  lines.push(`Updated:     ${record.updatedAt}`);
  return lines.join("\n");
}