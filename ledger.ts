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
import { existsSync } from "fs";
import { mkdir, readFile, appendFile, writeFile, rename, open, rm, stat } from "fs/promises";
import { dirname, join, resolve } from "path";
import { homedir } from "os";

// ── Types ────────────────────────────────────────────────────────────

export const STATUS_VALUES = ["hypothesis", "investigating", "confirmed", "blocked", "killed", "reported"] as const;
export type CaseStatus = (typeof STATUS_VALUES)[number];

export const CONFIDENCE_VALUES = ["low", "medium", "high"] as const;
export type CaseConfidence = (typeof CONFIDENCE_VALUES)[number];

export const SEVERITY_VALUES = ["info", "low", "medium", "high", "critical"] as const;
export type CaseSeverity = (typeof SEVERITY_VALUES)[number];

export const PRIORITY_VALUES = ["P0", "P1", "P2", "P3", "P4"] as const;
export type CasePriority = (typeof PRIORITY_VALUES)[number];

export const SEARCH_FIELD_VALUES = ["title", "summary", "evidence", "impact", "target", "endpoint", "bugClass", "poc"] as const;

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
  summary?: string;
  evidence?: string;
  impact?: string;
  nextStep?: string;
  poc?: string;
  remediation?: string;
  references?: string[];
  blockers?: string[];
  tags?: string[];
  /** Explicit assumptions or unknowns to avoid overstating exploitability. */
  assumptions?: string[];
  /** Verification of an on-disk PoC run (set only by promoteFindingResult). */
  pocVerified?: { path: string; exitCode: number; ranAt: string; output?: string };
  /** ISO timestamp when CaseReport first wrote the markdown report. */
  reportedAt?: string;
  /** Path to the generated markdown report (set only by writeCaseReport). */
  reportPath?: string;
  linkedCaseIds: string[];
  createdAt: string;
  updatedAt: string;
};

type CaseInput = {
  title: string;
  status?: CaseStatus;
  confidence?: CaseConfidence;
  severity?: CaseSeverity;
  priority?: CasePriority;
  target?: string;
  endpoint?: string;
  bugClass?: string;
  summary?: string;
  evidence?: string;
  impact?: string;
  nextStep?: string;
  poc?: string;
  remediation?: string;
  references?: string[];
  blockers?: string[];
  tags?: string[];
  assumptions?: string[];
};

type NormalizedCaseInput = Partial<CaseInput> & {
  linkedCaseIds?: string[];
  /** Internal-only fields used by ledger-level helpers (not settable via tools). */
  pocVerified?: CaseRecord["pocVerified"];
  reportedAt?: string;
  reportPath?: string;
};

type CaseUpdate = Partial<CaseInput>;

type CaseUpdateResult = {
  record: CaseRecord;
  changed: boolean;
  reason?: string;
};

type CaseAddResult = {
  record: CaseRecord;
  created: boolean;
  reason?: string;
};

type CaseLinkResult = {
  source: CaseRecord;
  target: CaseRecord;
  changed: boolean;
  reason?: string;
};

type CaseSearchField = (typeof SEARCH_FIELD_VALUES)[number];

type CaseSearchOptions = {
  query?: string;
  field?: CaseSearchField;
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

function normalizeMatchText(value: string | undefined): string {
  return normalizeText(value)?.toLowerCase().replace(/\s+/g, " ") ?? "";
}

function hasOwn<T extends object>(value: T, key: PropertyKey): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function hasDefined<T extends object>(value: T, key: keyof T): boolean {
  return hasOwn(value, key) && value[key] !== undefined;
}

function assertNoDirectLinkMutation(value: object): void {
  if (hasOwn(value, "linkedCaseIds")) {
    throw new Error("Case links must be changed with linkCases or unlinkCases");
  }
}

function normalizeOptionalText(
  input: NormalizedCaseInput,
  field: keyof Pick<
    CaseInput,
    "target" | "endpoint" | "bugClass" | "summary" | "evidence" | "impact" | "nextStep" | "poc" | "remediation"
  >,
  existing?: CaseRecord,
): string | undefined {
  if (hasOwn(input, field)) return normalizeText(input[field]);
  return existing?.[field];
}

function stableShortId(input: string): string {
  return createHash("sha1").update(input).digest("hex").slice(0, 10);
}

function casesMateriallyEqual(left: CaseRecord, right: CaseRecord): boolean {
  const normalize = (r: CaseRecord) => JSON.stringify({ ...r, updatedAt: "", createdAt: "" });
  return normalize(left) === normalize(right);
}

function noChangeReason(current: CaseRecord, update: CaseUpdate): string {
  if (update.status && update.status === current.status) {
    return `Case is already ${current.status}; no material fields changed.`;
  }
  return "No material fields changed.";
}

function findDuplicateCase(records: CaseRecord[], candidate: CaseRecord): CaseRecord | undefined {
  const title = normalizeMatchText(candidate.title);
  if (!title) return undefined;

  return records.find((record) =>
    record.status !== "killed" &&
    normalizeMatchText(record.title) === title &&
    normalizeMatchText(record.target) === normalizeMatchText(candidate.target) &&
    normalizeMatchText(record.endpoint) === normalizeMatchText(candidate.endpoint) &&
    normalizeMatchText(record.bugClass) === normalizeMatchText(candidate.bugClass)
  );
}

// ── Ledger Path ──────────────────────────────────────────────────────

let ledgerPathOverride: string | undefined;
let mutationQueue: Promise<void> = Promise.resolve();

function firstEnv(...names: string[]): { name: string; value: string } | undefined {
  for (const name of names) {
    const value = process.env[name]?.trim();
    if (value) return { name, value };
  }
  return undefined;
}

import { setTimeout as sleep } from "timers/promises";

function detectWorkspaceRoot(): string {
  const envs = ["CASEFILE_WORKSPACE_ROOT", "CODEX_WORKSPACE_ROOT", "PI_WORKSPACE_ROOT", "GITHUB_WORKSPACE", "PWD"];
  for (const e of envs) if (process.env[e]) return resolve(process.env[e]!);

  let curr = resolve(process.cwd());
  for (let i = 0; i < 20; i++) {
    if (existsSync(join(curr, ".git"))) return curr;
    const parent = dirname(curr);
    if (parent === curr) break;
    curr = parent;
  }
  return resolve(process.cwd());
}

export function getCasefilePath(): string {
  if (ledgerPathOverride) return ledgerPathOverride;

  const explicitPath = firstEnv("CASEFILE_PATH", "CODEX_CASEFILE_PATH", "PI_CASEFILE_PATH");
  if (explicitPath) return resolve(explicitPath.value);

  const scopeConfig = firstEnv("CASEFILE_SCOPE", "CODEX_CASEFILE_SCOPE", "PI_CASEFILE_SCOPE");
  const scope = (scopeConfig?.value.toLowerCase() || "project");
  if (scope === "global" && scopeConfig?.name === "PI_CASEFILE_SCOPE") {
    return join(homedir(), ".pi", "casefile", "casefile.jsonl");
  }
  if (scope === "global") return join(homedir(), ".casefile", "casefile.jsonl");

  const projectDir = scopeConfig?.name === "CASEFILE_SCOPE" || scopeConfig?.name === "CODEX_CASEFILE_SCOPE"
    ? ".casefile"
    : ".pi";
  return join(detectWorkspaceRoot(), projectDir, "casefile.jsonl");
}

function getCasefileReportDir(): string {
  return join(dirname(getCasefilePath()), "report");
}

async function acquireLedgerLock(): Promise<() => Promise<void>> {
  const ledgerPath = getCasefilePath();
  const lockPath = `${ledgerPath}.lock`;
  await mkdir(dirname(ledgerPath), { recursive: true });

  const timeoutMs = 15_000;
  const staleMs = 30_000;
  const started = Date.now();

  while (true) {
    try {
      const handle = await open(lockPath, "wx");
      await handle.writeFile(JSON.stringify({ pid: process.pid, createdAt: nowIso() }), "utf8");
      await handle.close();
      return async () => {
        await rm(lockPath, { force: true });
      };
    } catch (error: unknown) {
      if ((error as any)?.code !== "EEXIST") throw error;

      try {
        const info = await stat(lockPath);
        if (Date.now() - info.mtimeMs > staleMs) {
          await rm(lockPath, { force: true });
          continue;
        }
      } catch {
        continue;
      }

      if (Date.now() - started > timeoutMs) {
        throw new Error(`Timed out waiting for casefile lock: ${lockPath}`);
      }
      await sleep(50);
    }
  }
}

async function withLedgerMutation<T>(fn: () => Promise<T>): Promise<T> {
  const run = mutationQueue.then(async () => {
    const release = await acquireLedgerLock();
    try {
      return await fn();
    } finally {
      await release();
    }
  });

  mutationQueue = run.then(() => undefined, () => undefined);
  return run;
}

/** For testing only */
export function setCasefilePath(path: string | undefined): void {
  ledgerPathOverride = path;
}

// ── Normalize ─────────────────────────────────────────────────────────

function validateCase(record: CaseRecord): void {
  if (!record.title.trim()) throw new Error("Case title cannot be empty");
  if (record.status === "confirmed" && (!record.evidence || !record.poc)) {
    throw new Error("Confirmed cases require both evidence and poc");
  }
  if (record.status === "blocked" && (record.blockers ?? []).length === 0) {
    throw new Error("Blocked cases require at least one blocker");
  }
  if (
    record.status === "killed" &&
    !record.evidence &&
    !record.nextStep &&
    (record.blockers ?? []).length === 0 &&
    (record.assumptions ?? []).length === 0
  ) {
    throw new Error("Killed cases require evidence, next step, blockers, or assumptions explaining why");
  }
  if (record.status === "reported" && !record.poc && !record.remediation && (record.references ?? []).length === 0) {
    throw new Error("Reported cases require poc, remediation, or references");
  }
}

// ── State-machine transition gate ─────────────────────────────────────
// Enforces the cyber-workflow pipeline on status *changes*. Field-only
// updates (no status change) skip this gate. Killed/reported are terminal.
// Per-target-state field gates remain in validateCase; this only checks the
// transition itself and the fields the caller provided on this step.
//
// record — promotion must re-assert evidence at the promotion call. This is
// stricter than checking inherited values but makes the gate deterministic
// (confidence always has a default, so checking the merged record could never
// fail). Upgrade path: none, this is the intended shape.
function validateTransition(
  from: CaseStatus,
  to: CaseStatus,
  update: CaseUpdate,
  current?: CaseRecord,
): void {
  if (from === to) return; // no-op status restatement is handled by material-equality check

  // Terminal states are immutable.
  if (from === "killed") {
    throw new Error(`Cannot revive a killed case; open a new case if the lead is revived (was ${from} → ${to})`);
  }
  if (from === "reported") {
    throw new Error(`Cannot mutate a reported case; file a follow-up case instead (was ${from} → ${to})`);
  }

  // killed is reachable from anywhere; validateCase already enforces its supporting fields.
  if (to === "killed") return;
  // blocked is reachable from any non-terminal state; validateCase enforces blockers[].
  if (to === "blocked") return;

  type Rule = (u: CaseUpdate, current?: CaseRecord) => string | null;
  const transitions: Partial<Record<CaseStatus, Partial<Record<CaseStatus, Rule>>>> = {
    hypothesis: {
      investigating: (u) =>
        !u.evidence ? "INVESTIGATING requires evidence (source→sink trace)" :
        !u.confidence ? "INVESTIGATING requires confidence level" :
        null,
      confirmed: () => "Cannot jump hypothesis → confirmed; promote to investigating first",
      reported: () => "Cannot jump hypothesis → reported; confirm first",
      // hypothesis → blocked handled by validateCase
    },
    investigating: {
      // confirmed is only reachable through promoteFindingResult, which verifies an on-disk PoC.
      confirmed: () => "investigating → confirmed requires a verified PoC run; use the promote_finding tool",
      hypothesis: () => null, // downgrade allowed
      // investigating → blocked handled by validateCase
    },
    confirmed: {
      reported: (_, current) =>
        !current?.reportPath
          ? "confirmed → reported requires a report; run CaseReport first"
          : null,
      investigating: () => null, // rework allowed
      // confirmed → blocked handled by validateCase
    },
  };

  const rule = transitions[from]?.[to];
  if (rule === undefined) {
    throw new Error(`Invalid transition: ${from} → ${to}`);
  }
  const reason = rule(update, current);
  if (reason) {
    throw new Error(`Cannot transition ${from} → ${to}: ${reason}`);
  }
}

function validateNewCaseInput(input: CaseInput): void {
  if (input.status && input.status !== "hypothesis" && input.status !== "investigating") {
    throw new Error("New cases must start as hypothesis or investigating; promote with CaseUpdate after validation");
  }
  if (input.status === "investigating") {
    if (!input.evidence) {
      throw new Error("New investigating cases require evidence (source→sink trace)");
    }
    if (!input.confidence) {
      throw new Error("New investigating cases require a confidence level");
    }
  }
}

// validateTransition before validateCase — transition errors are more
// actionable than the generic target-state field errors. Upgrade path: none,
// this is the intended shape.
function buildRecord(
  input: NormalizedCaseInput,
  existing?: CaseRecord,
): CaseRecord {
  const timestamp = nowIso();
  const title = (hasOwn(input, "title") ? input.title : existing?.title)?.trim() ?? "";
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
    target: normalizeOptionalText(input, "target", existing),
    endpoint: normalizeOptionalText(input, "endpoint", existing),
    bugClass: normalizeOptionalText(input, "bugClass", existing),
    summary: normalizeOptionalText(input, "summary", existing),
    evidence: normalizeOptionalText(input, "evidence", existing),
    impact: normalizeOptionalText(input, "impact", existing),
    nextStep: normalizeOptionalText(input, "nextStep", existing),
    poc: normalizeOptionalText(input, "poc", existing),
    remediation: normalizeOptionalText(input, "remediation", existing),
    references: normalizeList(input.references ?? existing?.references),
    blockers: normalizeList(input.blockers ?? existing?.blockers),
    tags: normalizeList(input.tags ?? existing?.tags),
    assumptions: normalizeList(input.assumptions ?? existing?.assumptions),
    pocVerified: input.pocVerified ?? existing?.pocVerified,
    reportedAt: input.reportedAt ?? existing?.reportedAt,
    reportPath: input.reportPath ?? existing?.reportPath,
    linkedCaseIds: normalizeList(
      input.linkedCaseIds ?? existing?.linkedCaseIds,
    ).filter((lid) => lid !== id),
    createdAt: existing?.createdAt ?? timestamp,
    updatedAt: timestamp,
  };
}

function normalizeCase(
  input: NormalizedCaseInput,
  existing?: CaseRecord,
): CaseRecord {
  const record = buildRecord(input, existing);
  validateCase(record);
  return record;
}

// ── Read (with dedup — last write wins) ────────────────────────────────

export async function readCasefile(): Promise<CaseRecord[]> {
  try {
    const raw = await readFile(getCasefilePath(), "utf8");
    const recordsMap = new Map<string, CaseRecord>();
    let lineNum = 0;

    for (const line of raw.split("\n")) {
      lineNum++;
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const parsed = JSON.parse(trimmed) as CaseRecord;
        recordsMap.set(parsed.id, parsed);
      } catch {
        throw new Error(`Invalid casefile JSON at line ${lineNum} in ${getCasefilePath()}`);
      }
    }
    return Array.from(recordsMap.values());
  } catch (error: unknown) {
    if ((error as any)?.code === "ENOENT") return [];
    throw error;
  }
}

// ── Write (full) ─────────────────────────────────────────────────────

async function writeCasefile(records: CaseRecord[]): Promise<void> {
  const ledgerPath = getCasefilePath();
  await mkdir(dirname(ledgerPath), { recursive: true });
  const body = records.map((r) => JSON.stringify(r)).join("\n");
  const tempPath = `${ledgerPath}.${randomUUID()}.tmp`;
  await writeFile(tempPath, body ? `${body}\n` : "", "utf8");
  await rename(tempPath, ledgerPath);
}

// ── Add (append-based) ───────────────────────────────────────────────

export async function addCaseResult(input: CaseInput): Promise<CaseAddResult> {
  return withLedgerMutation(async () => {
    assertNoDirectLinkMutation(input);
    validateNewCaseInput(input);
    const record = normalizeCase(input);
    const records = await readCasefile();
    const duplicate = findDuplicateCase(records, record);
    if (duplicate) {
      return {
        record: duplicate,
        created: false,
        reason: `Duplicate case exists: ${duplicate.id}`,
      };
    }

    const ledgerPath = getCasefilePath();
    await mkdir(dirname(ledgerPath), { recursive: true });
    await appendFile(ledgerPath, `${JSON.stringify(record)}\n`, "utf8");
    return { record, created: true };
  });
}

export async function addCase(input: CaseInput): Promise<CaseRecord> {
  const result = await addCaseResult(input);
  return result.record;
}

// ── Update (append-based — dedup on read picks up latest) ────────────

export async function updateCaseResult(
  id: string,
  update: CaseUpdate,
): Promise<CaseUpdateResult> {
  return withLedgerMutation(async () => {
    assertNoDirectLinkMutation(update);
    const records = await readCasefile();
    const current = records.find((r) => r.id === id);
    if (!current) {
      throw new Error(`Case not found: ${id}`);
    }
    const next = buildRecord(
      {
        ...(hasDefined(update, "title") ? { title: update.title } : {}),
        status: update.status ?? current.status,
        confidence: update.confidence ?? current.confidence,
        severity: update.severity ?? current.severity,
        priority: update.priority ?? current.priority,
        ...(hasDefined(update, "target") ? { target: update.target } : {}),
        ...(hasDefined(update, "endpoint") ? { endpoint: update.endpoint } : {}),
        ...(hasDefined(update, "bugClass") ? { bugClass: update.bugClass } : {}),
        ...(hasDefined(update, "summary") ? { summary: update.summary } : {}),
        ...(hasDefined(update, "evidence") ? { evidence: update.evidence } : {}),
        ...(hasDefined(update, "impact") ? { impact: update.impact } : {}),
        ...(hasDefined(update, "nextStep") ? { nextStep: update.nextStep } : {}),
        ...(hasDefined(update, "poc") ? { poc: update.poc } : {}),
        ...(hasDefined(update, "remediation") ? { remediation: update.remediation } : {}),
        references: update.references ?? current.references,
        blockers: update.blockers ?? current.blockers,
        tags: update.tags ?? current.tags,
        assumptions: update.assumptions ?? current.assumptions,
        linkedCaseIds: current.linkedCaseIds,
      },
      current,
    );

    // Enforce the state-machine transition before field gates so the model
    // sees the actionable transition reason (e.g. "requires poc, evidence,
    // impact, severity") rather than the generic validateCase message.
    if (update.status && update.status !== current.status) {
      validateTransition(current.status, next.status, update, current);
    }
    validateCase(next);

    if (casesMateriallyEqual(current, next)) {
      return { record: current, changed: false, reason: noChangeReason(current, update) };
    }

    const duplicate = findDuplicateCase(records.filter((r) => r.id !== id), next);
    if (duplicate) {
      return {
        record: current,
        changed: false,
        reason: `Update would create a duplicate of case ${duplicate.id}`,
      };
    }

    // Append updated record — dedup on read picks up the latest version
    const ledgerPath = getCasefilePath();
    await mkdir(dirname(ledgerPath), { recursive: true });
    await appendFile(ledgerPath, `${JSON.stringify(next)}\n`, "utf8");
    return { record: next, changed: true };
  });
}

// ── Promote (verified PoC required) ───────────────────────────────────

export type PocVerification = {
  path: string;
  exitCode: number;
  ranAt: string;
  output?: string;
};

/**
 * Promote an investigating case to confirmed after a verified PoC run.
 * This is the only privileged path to confirmed; direct CaseUpdate promotions
 * are rejected by validateTransition.
 */
export async function promoteFindingResult(
  id: string,
  verification: PocVerification,
): Promise<CaseUpdateResult> {
  return withLedgerMutation(async () => {
    const records = await readCasefile();
    const current = records.find((r) => r.id === id);
    if (!current) {
      throw new Error(`Case not found: ${id}`);
    }
    if (current.status !== "investigating") {
      throw new Error(`promote_finding requires an investigating case (current: ${current.status})`);
    }
    if (!current.poc) {
      throw new Error("CONFIRMED requires poc; set poc on the case first");
    }
    if (!current.evidence) {
      throw new Error("CONFIRMED requires evidence; set evidence on the case first");
    }
    if (!current.impact) {
      throw new Error("CONFIRMED requires impact; set impact on the case first");
    }
    if (!current.severity) {
      throw new Error("CONFIRMED requires severity; set severity on the case first");
    }
    if (verification.exitCode !== 0) {
      throw new Error(`PoC verification failed (exit ${verification.exitCode}); cannot promote to confirmed`);
    }

    const next = buildRecord(
      {
        status: "confirmed",
        pocVerified: verification,
      },
      current,
    );
    validateCase(next);

    const ledgerPath = getCasefilePath();
    await mkdir(dirname(ledgerPath), { recursive: true });
    await appendFile(ledgerPath, `${JSON.stringify(next)}\n`, "utf8");
    return { record: next, changed: true };
  });
}

// ── Link (atomic: single write for both directions) ──────────────────

export async function linkCases(
  sourceId: string,
  targetId: string,
): Promise<{ source: CaseRecord; target: CaseRecord }> {
  const { source, target } = await linkCasesResult(sourceId, targetId);
  return { source, target };
}

export async function linkCasesResult(
  sourceId: string,
  targetId: string,
): Promise<CaseLinkResult> {
  return withLedgerMutation(async () => {
    if (sourceId === targetId) {
      throw new Error("Cannot link a case to itself");
    }
    const records = await readCasefile();
    const source = records.find((r) => r.id === sourceId);
    const target = records.find((r) => r.id === targetId);
    if (!source) throw new Error(`Case not found: ${sourceId}`);
    if (!target) throw new Error(`Case not found: ${targetId}`);

    const alreadyLinked = source.linkedCaseIds.includes(targetId) && target.linkedCaseIds.includes(sourceId);
    if (alreadyLinked) {
      return { source, target, changed: false, reason: "Cases are already linked" };
    }

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
    return { source, target, changed: true };
  });
}

// ── Unlink (atomic: single write) ────────────────────────────────────

export async function unlinkCases(
  sourceId: string,
  targetId: string,
): Promise<{ source: CaseRecord; target: CaseRecord }> {
  const { source, target } = await unlinkCasesResult(sourceId, targetId);
  return { source, target };
}

export async function unlinkCasesResult(
  sourceId: string,
  targetId: string,
): Promise<CaseLinkResult> {
  return withLedgerMutation(async () => {
    const records = await readCasefile();
    const source = records.find((r) => r.id === sourceId);
    const target = records.find((r) => r.id === targetId);
    if (!source) throw new Error(`Case not found: ${sourceId}`);
    if (!target) throw new Error(`Case not found: ${targetId}`);

    const linked = source.linkedCaseIds.includes(targetId) || target.linkedCaseIds.includes(sourceId);
    if (!linked) {
      return { source, target, changed: false, reason: "Cases are not linked" };
    }

    const now = nowIso();
    source.linkedCaseIds = source.linkedCaseIds.filter((lid) => lid !== targetId);
    target.linkedCaseIds = target.linkedCaseIds.filter((lid) => lid !== sourceId);
    source.updatedAt = now;
    target.updatedAt = now;

    await writeCasefile(records);
    return { source, target, changed: true };
  });
}

// ── Search (field-scoped) ────────────────────────────────────────────

function caseHaystack(
  record: CaseRecord,
  field?: CaseSearchField,
): string {
  if (field) {
    const val = record[field];
    if (Array.isArray(val)) return val.join(" ").toLowerCase();
    return (typeof val === "string" ? val : String(val ?? "")).toLowerCase();
  }
  return Object.entries(record)
    .filter(([k]) => !["id", "createdAt", "updatedAt", "reportedAt", "reportPath"].includes(k))
    .map(([, v]) => (Array.isArray(v) ? v.join(" ") : String(v ?? "")))
    .filter(Boolean)
    .join("\n")
    .toLowerCase();
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
    record.summary ? `summary=${record.summary}` : undefined,
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
  const lines = [`═══ ${record.id} ═══`];
  for (const [key, val] of Object.entries(record)) {
    if (!val || (Array.isArray(val) && !val.length) || ["id", "createdAt", "updatedAt"].includes(key)) continue;
    const label = key.charAt(0).toUpperCase() + key.slice(1).replace(/([A-Z])/g, " $1");
    const display = Array.isArray(val)
      ? val.join(", ")
      : typeof val === "object"
        ? JSON.stringify(val)
        : val;
    lines.push(`${label.padEnd(12)} ${display}`);
  }
  return lines.concat([`Created:     ${record.createdAt}`, `Updated:     ${record.updatedAt}`]).join("\n");
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 70) || "case";
}

function mdSection(title: string, body?: string): string {
  return `## ${title}\n\n${body?.trim() || "Not recorded."}\n`;
}

export async function writeCaseReport(id: string): Promise<{ path: string; record: CaseRecord }> {
  return withLedgerMutation(async () => {
    const records = await readCasefile();
    const current = records.find((r) => r.id === id);
    if (!current) throw new Error(`Case not found: ${id}`);
    if (current.status !== "confirmed" && current.status !== "reported") {
      throw new Error("Case reports require a confirmed or reported case");
    }

    const reportDir = getCasefileReportDir();
    await mkdir(reportDir, { recursive: true });
    const reportPath = join(reportDir, `${slugify(current.title)}-${current.id}.md`);
    const references = current.references?.length ? current.references.map((r) => `- ${r}`).join("\n") : undefined;
    const assumptions = current.assumptions?.length ? current.assumptions.map((a) => `- ${a}`).join("\n") : undefined;
    const body = [
      `# ${current.title}`,
      `**Severity:** ${current.severity ?? "Not assessed"}`,
      `**Status:** ${current.status}`,
      `**Confidence:** ${current.confidence}`,
      current.priority ? `**Priority:** ${current.priority}` : undefined,
      current.target ? `**Target:** ${current.target}` : undefined,
      current.endpoint ? `**Endpoint:** ${current.endpoint}` : undefined,
      current.bugClass ? `**Bug class:** ${current.bugClass}` : undefined,
      "",
      mdSection("Summary", current.summary),
      mdSection("Steps to Reproduce / Evidence", current.evidence),
      mdSection("Proof of Concept", current.poc),
      mdSection("Impact", current.impact),
      mdSection("Remediation", current.remediation),
      mdSection("Assumptions and Uncertainty", assumptions),
      mdSection("References", references),
    ].filter(Boolean).join("\n");
    await writeFile(reportPath, body, "utf8");

    const next: CaseRecord = {
      ...current,
      reportPath,
      reportedAt: current.reportedAt ?? nowIso(),
      updatedAt: nowIso(),
    };
    if (!casesMateriallyEqual(current, next)) {
      const ledgerPath = getCasefilePath();
      await mkdir(dirname(ledgerPath), { recursive: true });
      await appendFile(ledgerPath, `${JSON.stringify(next)}\n`, "utf8");
    }
    return { path: reportPath, record: next };
  });
}
