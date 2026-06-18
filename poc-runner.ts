import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { extname } from "node:path";

export type PocRun = {
  path: string;
  exitCode: number;
  output: string;
  ranAt: string;
};

/**
 * Run a PoC script in an isolated docker sandbox.
 *
 * Python (.py) and shell (.sh) scripts are supported; anything else is run
 * as a shell script in alpine. The PoC path is mounted read-only.
 *
 * Naive runner — only supports local docker. Upgrade path: add
 * containerd/podman fallback, configurable timeout, or per-case runner image.
 */
export function runPoc(pocPath: string): PocRun {
  if (!existsSync(pocPath)) {
    throw new Error(`PoC not found on disk: ${pocPath}`);
  }

  const ext = extname(pocPath);
  const isPython = ext === ".py";
  const image = isPython ? "python:3.12-slim" : "alpine";
  const runner = isPython ? "python3" : "sh";
  const containerPath = `/workspace/poc${ext}`;

  const args = [
    "run",
    "--rm",
    "--network",
    "none",
    "-v",
    `${pocPath}:${containerPath}:ro`,
    image,
    runner,
    containerPath,
  ];

  const ranAt = new Date().toISOString();
  const result = spawnSync("docker", args, {
    encoding: "utf8",
    timeout: 30000,
    maxBuffer: 8 * 1024 * 1024,
  });

  const output = (result.stdout ?? "") + (result.stderr ?? "");
  return {
    path: pocPath,
    exitCode: result.status ?? (result.signal ? 1 : 0),
    output: output.slice(0, 4000),
    ranAt,
  };
}
