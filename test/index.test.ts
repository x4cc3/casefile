import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { join } from "path";
import { tmpdir } from "os";

import { setCasefilePath } from "../ledger.js";

mock.module("@earendil-works/pi-ai", () => ({
  StringEnum: (values: readonly string[]) => ({ enum: values }),
}));

mock.module("typebox", () => ({
  Type: {
    Array: (item: unknown, options?: Record<string, unknown>) => ({ item, ...options }),
    Number: (options?: Record<string, unknown>) => ({ type: "number", ...options }),
    Object: (properties: Record<string, unknown>, options?: Record<string, unknown>) => ({
      type: "object",
      properties,
      ...options,
    }),
    Optional: (schema: unknown) => schema,
    String: (options?: Record<string, unknown>) => ({ type: "string", ...options }),
  },
}));

mock.module("@earendil-works/pi-tui", () => ({
  Text: class Text {
    constructor(
      public text: string,
      public x: number,
      public y: number,
    ) {}
  },
  matchesKey: (data: string, key: string) => data === key,
  truncateToWidth: (value: string, width: number) => value.slice(0, width),
}));

type FakePi = {
  tools: Map<string, any>;
  commands: Map<string, any>;
  events: Map<string, any[]>;
  registerTool(tool: any): void;
  registerCommand(name: string, command: any): void;
  on(event: string, handler: any): void;
};

let tempDir: string;
let casefileExtension: (pi: any) => void;

function createFakePi(): FakePi {
  return {
    tools: new Map(),
    commands: new Map(),
    events: new Map(),
    registerTool(tool) {
      this.tools.set(tool.name, tool);
    },
    registerCommand(name, command) {
      this.commands.set(name, command);
    },
    on(event, handler) {
      this.events.set(event, [...(this.events.get(event) ?? []), handler]);
    },
  };
}

async function executeTool(pi: FakePi, name: string, params: Record<string, unknown>) {
  const tool = pi.tools.get(name);
  if (!tool) throw new Error(`Tool not registered: ${name}`);
  return tool.execute("test-call", params, new AbortController().signal, () => undefined, {});
}

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "casefile-index-test-"));
  setCasefilePath(join(tempDir, "casefile.jsonl"));
  casefileExtension = (await import("../index.ts")).default;
});

afterEach(async () => {
  setCasefilePath(undefined);
  await rm(tempDir, { recursive: true, force: true });
});

describe("casefile extension", () => {
  test("registers the expected tools, command, and lifecycle events", () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    expect([...pi.tools.keys()].sort()).toEqual([
      "CaseAdd",
      "CaseGet",
      "CaseLink",
      "CaseList",
      "CaseReport",
      "CaseSearch",
      "CaseUnlink",
      "CaseUpdate",
    ]);
    expect([...pi.commands.keys()]).toEqual(["casefile"]);
    expect(pi.events.has("session_start")).toBe(true);
    expect(pi.events.has("before_agent_start")).toBe(true);
    expect(pi.events.has("tool_result")).toBe(true);
  });

  test("executes the add, get, update, list, search, and report tools", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const added = await executeTool(pi, "CaseAdd", {
      title: "Sensitive file disclosure",
      status: "investigating",
      confidence: "medium",
      severity: "medium",
      priority: "P1",
      target: "app.example.test",
      endpoint: "/download",
      bug_class: "IDOR",
      summary: "Downloads are authorized by object ID only",
      evidence: "download?id=42 returns another user's file",
      next_step: "Confirm access as a second account",
      tags: ["idor"],
    });
    const record = added.details.record;

    const fetched = await executeTool(pi, "CaseGet", { id: record.id });
    expect(fetched.content[0].text).toContain("Sensitive file disclosure");
    expect(fetched.details.record.bugClass).toBe("IDOR");
    expect(fetched.details.record.summary).toBe("Downloads are authorized by object ID only");

    const updated = await executeTool(pi, "CaseUpdate", {
      id: record.id,
      status: "confirmed",
      confidence: "high",
      poc: "Fetch /download?id=42 with a different session",
    });
    expect(updated.details.changed).toBe(true);
    expect(updated.details.record.status).toBe("confirmed");
    expect(updated.details.record.poc).toContain("different session");

    const listed = await executeTool(pi, "CaseList", { status: "confirmed" });
    expect(listed.details.total).toBe(1);
    expect(listed.content[0].text).toContain(record.id);

    const searched = await executeTool(pi, "CaseSearch", {
      query: "different session",
      field: "poc",
      priority: "P1",
    });
    expect(searched.details.total).toBe(1);
    expect(searched.details.cases[0].id).toBe(record.id);

    const report = await executeTool(pi, "CaseReport", { id: record.id });
    expect(report.details.path).toMatch(/sensitive-file-disclosure-case_[a-f0-9]{10}\.md$/);
  });

  test("links and unlinks cases through registered tools", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    const first = await executeTool(pi, "CaseAdd", {
      title: "Open redirect",
      evidence: "next parameter accepts arbitrary URL",
    });
    const second = await executeTool(pi, "CaseAdd", {
      title: "OAuth callback abuse",
      evidence: "callback can consume redirected authorization code",
    });

    const linked = await executeTool(pi, "CaseLink", {
      source_id: first.details.record.id,
      target_id: second.details.record.id,
    });
    expect(linked.details.source.linkedCaseIds).toEqual([second.details.record.id]);
    expect(linked.details.target.linkedCaseIds).toEqual([first.details.record.id]);

    const unlinked = await executeTool(pi, "CaseUnlink", {
      source_id: first.details.record.id,
      target_id: second.details.record.id,
    });
    expect(unlinked.details.source.linkedCaseIds).toEqual([]);
    expect(unlinked.details.target.linkedCaseIds).toEqual([]);
  });

  test("injects only active cases into before_agent_start context", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    await executeTool(pi, "CaseAdd", {
      title: "Active <payload> lead",
      status: "investigating",
      summary: "This should not be injected",
      evidence: "Observed suspicious response",
      next_step: "Test <payload> safely",
    });
    await executeTool(pi, "CaseAdd", {
      title: "Killed duplicate",
      status: "killed",
      assumptions: ["Duplicate lead with no new evidence"],
    });
    await executeTool(pi, "CaseAdd", {
      title: "Already reported",
      status: "reported",
      remediation: "Patch shipped",
    });

    const handler = pi.events.get("before_agent_start")?.[0];
    expect(handler).toBeFunction();

    const result = await handler();
    expect(result.message.customType).toBe("casefile_summary");
    expect(result.message.display).toBe(false);
    expect(result.message.content).toContain("Active cases: 1 total");
    expect(result.message.content).toContain("Active ‹payload› lead");
    expect(result.message.content).toContain("Test ‹payload› safely");
    expect(result.message.content).not.toContain("This should not be injected");
    expect(result.message.content).not.toContain("Killed duplicate");
    expect(result.message.content).not.toContain("Already reported");
  });

  test("supports the non-ui dashboard command and status updates", async () => {
    const pi = createFakePi();
    casefileExtension(pi as any);

    await executeTool(pi, "CaseAdd", {
      title: "Stored XSS",
      status: "confirmed",
      evidence: "Payload renders in notes",
    });

    const notifications: string[] = [];
    const statuses: Record<string, string> = {};
    const ctx = {
      hasUI: false,
      ui: {
        notify(message: string) {
          notifications.push(message);
        },
        setStatus(key: string, value: string) {
          statuses[key] = value;
        },
      },
    };

    await pi.commands.get("casefile").handler("", ctx);
    expect(notifications[0]).toContain("Casefile: 1 total");
    expect(notifications[0]).toContain("confirmed:1");

    const handler = pi.events.get("tool_result")?.[0];
    expect(handler).toBeFunction();
    await handler({ toolName: "CaseAdd" }, ctx);
    expect(statuses.casefile).toBe("1 cases");
  });
});
