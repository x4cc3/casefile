import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { mkdtemp, rm } from "fs/promises";
import { join } from "path";
import { tmpdir } from "os";

import { createCasefileMcpServer } from "../mcp/server.ts";
import { readCasefile, setCasefilePath } from "../ledger.ts";

let tempDir: string;

async function connectCasefileMcp() {
  const server = createCasefileMcpServer();
  const client = new Client({
    name: "casefile-test-client",
    version: "1.0.0",
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return { client, server };
}

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "casefile-mcp-test-"));
  setCasefilePath(join(tempDir, "casefile.jsonl"));
});

afterEach(async () => {
  setCasefilePath(undefined);
  await rm(tempDir, { recursive: true, force: true });
});

describe("casefile MCP server", () => {
  test("registers casefile tools and uses the shared ledger", async () => {
    const { client, server } = await connectCasefileMcp();
    try {
      const tools = await client.listTools();
      expect(tools.tools.map((tool) => tool.name).sort()).toEqual([
        "casefile_add",
        "casefile_count",
        "casefile_get",
        "casefile_link",
        "casefile_list",
        "casefile_report",
        "casefile_search",
        "casefile_unlink",
        "casefile_update",
      ]);

      const added = await client.callTool({
        name: "casefile_add",
        arguments: {
          title: "Codex SSRF candidate",
          status: "investigating",
          confidence: "medium",
          target: "api.example.test",
          evidence: "Backend fetches user-provided URLs",
          tags: ["ssrf"],
        },
      });
      const created = added.structuredContent as any;
      expect(created.created).toBe(true);
      expect(created.record.title).toBe("Codex SSRF candidate");

      const updated = await client.callTool({
        name: "casefile_update",
        arguments: {
          id: created.record.id,
          status: "confirmed",
          confidence: "high",
          severity: "high",
          poc: "Request the fetch endpoint with a collaborator URL and observe the callback",
        },
      });
      expect((updated.structuredContent as any).record.status).toBe("confirmed");

      const searched = await client.callTool({
        name: "casefile_search",
        arguments: {
          query: "collaborator",
          field: "poc",
        },
      });
      expect((searched.structuredContent as any).total).toBe(1);

      const listed = await client.callTool({
        name: "casefile_list",
        arguments: {
          status: "confirmed",
          tag: "ssrf",
        },
      });
      expect((listed.structuredContent as any).total).toBe(1);

      const records = await readCasefile();
      expect(records).toHaveLength(1);
      expect(records[0].id).toBe(created.record.id);
    } finally {
      await client.close();
      await server.close();
    }
  });
});
