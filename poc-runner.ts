import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { extname } from "node:path";

export type PocRun = {
  path: string;
  exitCode: number;
  output: string;
  ranAt: string;
  sandbox: boolean;
};

/**
 * Run a PoC script. Supports docker sandbox (default) or local execution.
 *
 * Python (.py) and shell (.sh) scripts are supported.
 */
export function runPoc(pocPath: string, useSandbox = true): PocRun {
  if (!existsSync(pocPath)) {
    throw new Error(`PoC not found on disk: ${pocPath}`);
  }

  const ext = extname(pocPath);
  const isPython = ext === ".py";
  const ranAt = new Date().toISOString();

  if (useSandbox) {
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
      sandbox: true,
    };
  }

  // Local execution
  const command = isPython ? "python3" : "sh";
  const result = spawnSync(command, [pocPath], {
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
    sandbox: false,
  };
}
