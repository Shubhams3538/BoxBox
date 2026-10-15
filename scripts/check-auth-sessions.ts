#!/usr/bin/env bun

import { type SmokeContext } from "./auth-smoke/context";
import { clearCredentials, redactedMessage } from "./auth-smoke/credentials";
import { createFixture } from "./auth-smoke/fixtures";
import {
  buildBinary,
  killAndWait,
  reservePort,
  startServer,
} from "./auth-smoke/process";
import { checkBackupRollback } from "./auth-smoke/scenarios/backup-rollback";
import { checkMissingStore } from "./auth-smoke/scenarios/missing-store";
import { checkSessions } from "./auth-smoke/scenarios/sessions";
import { checkStorageFailures } from "./auth-smoke/scenarios/storage-failures";
import { checkStrictStore } from "./auth-smoke/scenarios/strict-store";
import { type Result } from "./auth-smoke/types";
import { type Subprocess } from "bun";
import { chmodSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

type CliOptions =
  { kind: "help" } | { kind: "run"; binaryPath: string | undefined };

function parseArgs(args: string[]): CliOptions {
  if (args.length === 1 && args[0] === "--help") return { kind: "help" };

  let binaryPath: string | undefined;
  let binarySeen = false;
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === "--binary") {
      const value = args[index + 1];
      if (!value || value.startsWith("--")) {
        throw new Error("--binary requires an existing server binary path");
      }
      if (binarySeen) throw new Error("--binary may be specified only once");
      binaryPath = resolve(value);
      binarySeen = true;
      index++;
      continue;
    }
    if (argument.startsWith("--binary=")) {
      const value = argument.slice("--binary=".length);
      if (!value)
        throw new Error("--binary requires an existing server binary path");
      if (binarySeen) throw new Error("--binary may be specified only once");
      binaryPath = resolve(value);
      binarySeen = true;
      continue;
    }
    throw new Error("Unknown argument");
  }

  return { kind: "run", binaryPath };
}

function usage(): void {
  console.log(
    "Usage: bun scripts/check-auth-sessions.ts [--binary /path/to/boxbox]\n" +
      "Without --binary, builds backend/cmd/server into a private temporary directory.",
  );
}

function printResults(results: Result[]): void {
  console.log("| Scenario | Result | Evidence |");
  console.log("| --- | --- | --- |");
  for (const result of results) {
    console.log(
      `| ${result.scenario} | ${result.outcome} | ${result.evidence} |`,
    );
  }
}

async function runSmoke(): Promise<void> {
  const results: Result[] = [];
  const processes: Subprocess[] = [];
  let tempRoot: string | undefined;
  let failure: string | undefined;
  const issuedTokens: string[] = [];
  let interrupted = false;
  const onInterrupt = () => {
    interrupted = true;
    for (const proc of processes) {
      if (proc.exitCode === null) {
        try {
          proc.kill("SIGKILL");
        } catch {
          // Cleanup awaits the process handle and reports any failure.
        }
      }
    }
  };
  try {
    const options = parseArgs(Bun.argv.slice(2));
    if (options.kind === "help") {
      usage();
      return;
    }
    process.on("SIGINT", onInterrupt);
    process.on("SIGTERM", onInterrupt);

    tempRoot = mkdtempSync(join(tmpdir(), "boxbox-auth-sessions-"));
    chmodSync(tempRoot, 0o700);
    const repoRoot = resolve(import.meta.dir, "..");
    const backendDir = join(repoRoot, "backend");
    let binaryPath = options.binaryPath;
    if (binaryPath !== undefined) {
      let binaryIsFile = false;
      try {
        binaryIsFile = statSync(binaryPath).isFile();
      } catch {
        // Keep user-supplied paths out of diagnostics.
      }
      if (!binaryIsFile)
        throw new Error("--binary must point to an existing file");
    } else {
      binaryPath = await buildBinary(tempRoot, backendDir, processes);
    }

    const fixture = await createFixture(tempRoot, await reservePort());
    const context: SmokeContext = {
      ...fixture,
      binaryPath,
      backendDir,
      processes,
      issuedTokens,
      results,
    };
    let server = await startServer(
      binaryPath,
      fixture.configPath,
      backendDir,
      fixture.port,
      processes,
      "initial server",
    );
    const sessions = await checkSessions(context, server);
    server = await checkStorageFailures(
      context,
      sessions.server,
      sessions.activeAfterRestart,
    );
    await checkStrictStore(context, server);
    server = await checkBackupRollback(context);
    await checkMissingStore(context, server);
  } catch (error) {
    failure = redactedMessage(error);
    results.push({ scenario: "Smoke run", outcome: "FAIL", evidence: failure });
  } finally {
    for (const proc of processes) {
      try {
        await killAndWait(proc);
      } catch {
        failure = failure
          ? `${failure}; process cleanup failed`
          : "Process cleanup failed";
      }
    }
    if (tempRoot !== undefined) {
      try {
        rmSync(tempRoot, { recursive: true, force: true });
      } catch {
        failure = failure
          ? `${failure}; temporary-file cleanup failed`
          : "Temporary-file cleanup failed";
      }
    }
    process.removeListener("SIGINT", onInterrupt);
    clearCredentials();
    issuedTokens.length = 0;
    process.removeListener("SIGTERM", onInterrupt);
  }
  if (interrupted && !failure) failure = "Interrupted before completion";

  if (failure && !results.some((result) => result.outcome === "FAIL")) {
    results.push({ scenario: "Cleanup", outcome: "FAIL", evidence: failure });
  }
  printResults(results);
  if (failure) {
    console.error(`Auth session smoke check failed: ${failure}`);
    process.exitCode = 1;
  }
}

await runSmoke();
