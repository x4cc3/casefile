import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "fs/promises";
import { join } from "path";
import { tmpdir } from "os";

import {
  addCase,
  addCaseResult,
  getCasefilePath,
  linkCases,
  linkCasesResult,
  readCasefile,
  searchCases,
  setCasefilePath,
  unlinkCases,
  unlinkCasesResult,
  updateCaseResult,
  writeCaseReport,
} from "../ledger.ts";

let tempDir: string;
let ledgerPath: string;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "casefile-test-"));
  ledgerPath = join(tempDir, "casefile.jsonl");
  setCasefilePath(ledgerPath);
});

afterEach(async () => {
  setCasefilePath(undefined);
  await rm(tempDir, { recursive: true, force: true });
});

describe("casefile ledger", () => {
  test("adds cases with defaults and persists them as jsonl", async () => {
    const record = await addCase({
      title: " SSRF candidate ",
      target: "api.example.test",
      summary: "Server fetches attacker-controlled URLs",
      tags: [" ssrf ", "ssrf", ""],
    });

    expect(record.id).toMatch(/^case_[a-f0-9]{10}$/);
    expect(record.title).toBe("SSRF candidate");
    expect(record.status).toBe("hypothesis");
    expect(record.confidence).toBe("low");
    expect(record.tags).toEqual(["ssrf"]);

    const records = await readCasefile();
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      id: record.id,
      title: "SSRF candidate",
      target: "api.example.test",
      summary: "Server fetches attacker-controlled URLs",
    });
  });

  test("supports neutral casefile env vars while preserving legacy pi defaults", async () => {
    const previous = {
      CASEFILE_PATH: process.env.CASEFILE_PATH,
      CASEFILE_SCOPE: process.env.CASEFILE_SCOPE,
      PI_CASEFILE_PATH: process.env.PI_CASEFILE_PATH,
      PI_CASEFILE_SCOPE: process.env.PI_CASEFILE_SCOPE,
    };

    try {
      setCasefilePath(undefined);
      process.env.CASEFILE_PATH = join(tempDir, "neutral.jsonl");
      process.env.PI_CASEFILE_PATH = join(tempDir, "pi.jsonl");
      expect(getCasefilePath()).toBe(join(tempDir, "neutral.jsonl"));

      delete process.env.CASEFILE_PATH;
      delete process.env.PI_CASEFILE_PATH;
      process.env.CASEFILE_SCOPE = "project";
      expect(getCasefilePath()).toBe(join(process.cwd(), ".casefile", "casefile.jsonl"));

      delete process.env.CASEFILE_SCOPE;
      process.env.PI_CASEFILE_SCOPE = "project";
      expect(getCasefilePath()).toBe(join(process.cwd(), ".pi", "casefile.jsonl"));
    } finally {
      for (const [key, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
      setCasefilePath(ledgerPath);
    }
  });

  test("deduplicates active cases with the same title and scope", async () => {
    const first = await addCaseResult({
      title: " SSRF candidate ",
      target: "api.example.test",
      bugClass: "SSRF",
      evidence: "Observed URL fetch",
    });
    expect(first.created).toBe(true);

    const duplicate = await addCaseResult({
      title: "ssrf   candidate",
      target: "api.example.test",
      bugClass: "ssrf",
      evidence: "Repeated audit note",
    });
    expect(duplicate.created).toBe(false);
    expect(duplicate.record.id).toBe(first.record.id);
    expect(duplicate.reason).toContain(first.record.id);

    const raw = await readFile(ledgerPath, "utf8");
    expect(raw.trim().split("\n")).toHaveLength(1);
  });

  test("keeps same-title cases separate when scope differs or becomes specific", async () => {
    const generic = await addCaseResult({
      title: "SSRF candidate",
      evidence: "Generic audit note",
    });
    const scoped = await addCaseResult({
      title: "SSRF candidate",
      target: "api.example.test",
      evidence: "Scoped audit note",
    });
    const otherEndpoint = await addCaseResult({
      title: "SSRF candidate",
      target: "api.example.test",
      endpoint: "/fetch",
      evidence: "Endpoint-specific audit note",
    });

    expect(generic.created).toBe(true);
    expect(scoped.created).toBe(true);
    expect(otherEndpoint.created).toBe(true);
    expect(new Set([generic.record.id, scoped.record.id, otherEndpoint.record.id]).size).toBe(3);
    expect(await readCasefile()).toHaveLength(3);
  });

  test("updates by appending a new version and treats no-op updates as unchanged", async () => {
    const record = await addCase({
      title: "IDOR in export",
      status: "investigating",
      evidence: "Observed sequential IDs",
    });

    const updated = await updateCaseResult(record.id, {
      status: "confirmed",
      confidence: "high",
      severity: "high",
      poc: "Request /exports/123 as another user",
    });
    expect(updated.changed).toBe(true);
    expect(updated.record).toMatchObject({
      status: "confirmed",
      confidence: "high",
      severity: "high",
    });

    const noOp = await updateCaseResult(record.id, { status: "confirmed" });
    expect(noOp.changed).toBe(false);
    expect(noOp.reason).toContain("already confirmed");

    const raw = await readFile(ledgerPath, "utf8");
    expect(raw.trim().split("\n")).toHaveLength(2);
    expect(await readCasefile()).toHaveLength(1);
  });

  test("prevents duplicate titles and scopes during update", async () => {
    await addCase({ title: "First Case" });
    const second = await addCase({ title: "Second Case" });

    const result = await updateCaseResult(second.id, { title: "First Case" });
    expect(result.changed).toBe(false);
    expect(result.reason).toContain("duplicate of case");

    const records = await readCasefile();
    expect(records.filter((r) => r.title === "First Case")).toHaveLength(1);
  });

  test("clears optional text fields with an empty string update", async () => {
    const record = await addCase({
      title: "Stale finding",
      evidence: "Original evidence",
      summary: "Original summary",
      impact: "Original impact",
      nextStep: "Original next step",
    });

    const result = await updateCaseResult(record.id, {
      evidence: "",
      summary: "Updated summary",
      nextStep: "  ",
    });

    expect(result.changed).toBe(true);
    expect(result.record.evidence).toBeUndefined();
    expect(result.record.summary).toBe("Updated summary");
    expect(result.record.impact).toBe("Original impact");
    expect(result.record.nextStep).toBeUndefined();
  });

  test("enforces workflow validation for confirmed, blocked, killed, and reported cases", async () => {
    await expect(addCase({ title: "Empty confirmed", status: "confirmed" }))
      .rejects
      .toThrow("New cases must start as hypothesis or investigating");

    await expect(addCase({
      title: "Instant confirmed",
      status: "confirmed",
      evidence: "Single observation",
    }))
      .rejects
      .toThrow("New cases must start as hypothesis or investigating");

    const weakLead = await addCase({
      title: "Code review only SSRF",
      status: "investigating",
      evidence: "URL is fetched after hostname validation",
    });
    await expect(updateCaseResult(weakLead.id, { status: "confirmed" }))
      .rejects
      .toThrow("Confirmed cases require both evidence and poc");

    const terminalLead = await addCase({
      title: "Terminal-state validation",
      status: "investigating",
    });

    await expect(updateCaseResult(terminalLead.id, { status: "blocked" }))
      .rejects
      .toThrow("Blocked cases require at least one blocker");

    await expect(updateCaseResult(terminalLead.id, { status: "killed" }))
      .rejects
      .toThrow("Killed cases require evidence, next step, blockers, or assumptions");

    const duplicateLead = await addCase({
      title: "Duplicate lead",
      status: "investigating",
    });
    await expect(updateCaseResult(duplicateLead.id, {
      status: "killed",
      assumptions: ["Duplicate of case_123; no new evidence"],
    })).resolves.toMatchObject({
      record: {
        status: "killed",
        assumptions: ["Duplicate of case_123; no new evidence"],
      },
    });

    await expect(addCase({ title: "Reported without report data", status: "reported" }))
      .rejects
      .toThrow("New cases must start as hypothesis or investigating");
  });

  test("links and unlinks cases bidirectionally", async () => {
    const primitive = await addCase({
      title: "Open redirect",
      evidence: "redirect_url is trusted without validation",
    });
    const escalation = await addCase({
      title: "OAuth token theft",
      evidence: "Redirect can target attacker callback",
    });

    const linked = await linkCases(primitive.id, escalation.id);
    expect(linked.source.linkedCaseIds).toEqual([escalation.id]);
    expect(linked.target.linkedCaseIds).toEqual([primitive.id]);

    const duplicateLink = await linkCasesResult(primitive.id, escalation.id);
    expect(duplicateLink.changed).toBe(false);
    expect(duplicateLink.reason).toBe("Cases are already linked");

    const afterLink = await readCasefile();
    expect(afterLink.find((r) => r.id === primitive.id)?.linkedCaseIds).toEqual([escalation.id]);
    expect(afterLink.find((r) => r.id === escalation.id)?.linkedCaseIds).toEqual([primitive.id]);

    await unlinkCases(primitive.id, escalation.id);
    const duplicateUnlink = await unlinkCasesResult(primitive.id, escalation.id);
    expect(duplicateUnlink.changed).toBe(false);
    expect(duplicateUnlink.reason).toBe("Cases are not linked");

    const afterUnlink = await readCasefile();
    expect(afterUnlink.find((r) => r.id === primitive.id)?.linkedCaseIds).toEqual([]);
    expect(afterUnlink.find((r) => r.id === escalation.id)?.linkedCaseIds).toEqual([]);
  });

  test("rejects direct linked case mutation outside link helpers", async () => {
    const first = await addCase({
      title: "First chain step",
      evidence: "Primitive observed",
    });
    const second = await addCase({
      title: "Second chain step",
      evidence: "Escalation observed",
    });

    await expect(addCase({
      title: "Directly linked case",
      linkedCaseIds: [first.id],
    } as any))
      .rejects
      .toThrow("Case links must be changed with linkCases or unlinkCases");

    await expect(updateCaseResult(first.id, {
      linkedCaseIds: [second.id],
    } as any))
      .rejects
      .toThrow("Case links must be changed with linkCases or unlinkCases");

    const records = await readCasefile();
    expect(records.find((r) => r.id === first.id)?.linkedCaseIds).toEqual([]);
    expect(records.find((r) => r.id === second.id)?.linkedCaseIds).toEqual([]);
  });

  test("searches across fields and supports filters with pagination", async () => {
    await addCase({
      title: "GraphQL introspection",
      status: "investigating",
      severity: "medium",
      target: "api.example.test",
      summary: "GraphQL schema is exposed",
      evidence: "Schema exposes adminMutation",
      tags: ["graphql"],
    });
    const storedXss = await addCase({
      title: "Stored XSS",
      status: "investigating",
      severity: "high",
      evidence: "Payload persists in case notes",
      poc: "<img src=x onerror=alert(1)>",
      tags: ["xss"],
    });
    await updateCaseResult(storedXss.id, { status: "confirmed" });

    const graphql = await searchCases({ query: "adminMutation", field: "evidence" });
    expect(graphql.total).toBe(1);
    expect(graphql.cases[0].title).toBe("GraphQL introspection");

    const summary = await searchCases({ query: "schema is exposed", field: "summary" });
    expect(summary.total).toBe(1);
    expect(summary.cases[0].title).toBe("GraphQL introspection");

    const high = await searchCases({ severity: "high", tag: "xss", limit: 1, offset: 0 });
    expect(high.total).toBe(1);
    expect(high.cases[0].title).toBe("Stored XSS");
  });

  test("writes a markdown report for a case", async () => {
    const record = await addCase({
      title: "Account takeover through reset token reuse",
      status: "investigating",
      confidence: "high",
      severity: "critical",
      target: "auth.example.test",
      summary: "Reset tokens stay reusable after password changes",
      evidence: "Reset token remains valid after password change",
      impact: "Attacker can retain account access",
      poc: "Request two reset links, use both successfully",
      remediation: "Invalidate all outstanding reset tokens after first use",
      references: ["https://example.test/advisory"],
    });
    await updateCaseResult(record.id, { status: "confirmed" });

    const report = await writeCaseReport(record.id);
    expect(report.path).toMatch(/account-takeover-through-reset-token-reuse-case_[a-f0-9]{10}\.md$/);

    const body = await readFile(report.path, "utf8");
    expect(body).toContain("# Account takeover through reset token reuse");
    expect(body).toContain("**Severity:** critical");
    expect(body).toContain("## Summary");
    expect(body).toContain("Reset tokens stay reusable after password changes");
    expect(body).toContain("## Steps to Reproduce / Evidence");
    expect(body).toContain("Reset token remains valid after password change");
    expect(body).toContain("- https://example.test/advisory");
  });

  test("rejects reports for unconfirmed cases", async () => {
    const record = await addCase({
      title: "Needs validation",
      status: "investigating",
      evidence: "Static review only",
    });

    await expect(writeCaseReport(record.id))
      .rejects
      .toThrow("Case reports require a confirmed or reported case");
  });

  test("returns an empty ledger only when the file does not exist", async () => {
    await expect(readCasefile()).resolves.toEqual([]);

    await writeFile(ledgerPath, "{\"id\":\"case_valid\"}\n\nnot-json\n", "utf8");
    await expect(readCasefile()).rejects.toThrow("Invalid casefile JSON at line 3");
  });
});
