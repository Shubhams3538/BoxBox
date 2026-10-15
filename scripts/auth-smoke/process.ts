import { host, startupTimeoutMs, username } from "./constants";
import { fixtureCredentials, sanitizedEnvironment } from "./credentials";
import { spawn, type Subprocess } from "bun";
import { chmodSync, mkdirSync } from "node:fs";
import { createServer as createNetServer } from "node:net";
import { join } from "node:path";

type StartupOutcome =
  { kind: "ready" } | { kind: "exited"; code: number } | { kind: "timeout" };

export async function reservePort(): Promise<number> {
  const server = createNetServer();
  const listening = Promise.withResolvers<void>();
  server.once("error", () =>
    listening.reject(new Error("Could not reserve a localhost port")),
  );
  server.listen(0, host, () => listening.resolve());
  await listening.promise;

  const address = server.address();
  if (address === null || typeof address === "string") {
    const closing = Promise.withResolvers<void>();
    server.close((error) => {
      if (error)
        closing.reject(
          new Error("Could not release the reserved localhost port"),
        );
      else closing.resolve();
    });
    await closing.promise;
    throw new Error("Could not determine the reserved localhost port");
  }

  const closing = Promise.withResolvers<void>();
  server.close((error) => {
    if (error)
      closing.reject(
        new Error("Could not release the reserved localhost port"),
      );
    else closing.resolve();
  });
  await closing.promise;
  return address.port;
}

async function observeStartup(
  proc: Subprocess,
  port: number,
): Promise<StartupOutcome> {
  const baseUrl = `http://${host}:${port}`;
  const deadline = Date.now() + startupTimeoutMs;
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) return { kind: "exited", code: proc.exitCode };
    try {
      const response = await fetch(`${baseUrl}/health`, {
        headers: { Connection: "close" },
        signal: AbortSignal.timeout(1_000),
      });
      const ready = response.status === 200;
      await response.arrayBuffer();
      if (ready) return { kind: "ready" };
    } catch {
      // Keep checking the observable health endpoint until the server is ready or exits.
    }
    await Bun.sleep(100);
  }
  return { kind: "timeout" };
}

function startProcess(
  binaryPath: string,
  configPath: string,
  backendDir: string,
  processes: Subprocess[],
  stderr: "ignore" | "pipe" = "ignore",
): Subprocess {
  const env = sanitizedEnvironment();
  if (fixtureCredentials !== undefined) {
    env.BOXBOX_JWT_SECRET = fixtureCredentials.jwtSecret;
    env[`BOXBOX_USERS_${username}`] = fixtureCredentials.passwordHash;
  }
  let proc: Subprocess;
  try {
    proc = spawn({
      cmd: [binaryPath, "-config", configPath],
      cwd: backendDir,
      env,
      stdout: "ignore",
      stderr,
    });
  } catch {
    throw new Error("Could not start the supplied server binary");
  }
  processes.push(proc);
  return proc;
}

export async function killAndWait(proc: Subprocess): Promise<void> {
  if (proc.exitCode === null) {
    try {
      proc.kill("SIGKILL");
    } catch {
      // The process may have exited after the status check.
    }
  }
  await proc.exited;
}

export async function startServer(
  binaryPath: string,
  configPath: string,
  backendDir: string,
  port: number,
  processes: Subprocess[],
  label: string,
): Promise<Subprocess> {
  const proc = startProcess(binaryPath, configPath, backendDir, processes);
  const outcome = await observeStartup(proc, port);
  if (outcome.kind === "ready") return proc;
  if (outcome.kind === "timeout") await killAndWait(proc);
  else await proc.exited;
  throw new Error(`${label}: server did not become ready (${outcome.kind})`);
}

export async function expectStartupRefusal(
  binaryPath: string,
  configPath: string,
  backendDir: string,
  port: number,
  processes: Subprocess[],
  label: string,
  expectedFailure: string,
): Promise<void> {
  const proc = startProcess(
    binaryPath,
    configPath,
    backendDir,
    processes,
    "pipe",
  );
  const stderr = proc.stderr;
  if (typeof stderr === "number" || stderr === undefined) {
    await killAndWait(proc);
    throw new Error(`${label}: startup diagnostics were not piped`);
  }
  const diagnostics = new Response(stderr).text();
  const outcome = await observeStartup(proc, port);
  if (outcome.kind === "exited") {
    const code = await proc.exited;
    const output = await diagnostics;
    if (
      code !== 0 &&
      output.includes("initialize auth service:") &&
      output.includes(expectedFailure)
    )
      return;
    throw new Error(
      `${label}: startup did not report the expected session-store failure`,
    );
  }
  if (outcome.kind === "ready") {
    await killAndWait(proc);
    await diagnostics;
    throw new Error(`${label}: invalid session registry allowed startup`);
  }
  await killAndWait(proc);
  await diagnostics;
  throw new Error(
    `${label}: server did not refuse startup before the readiness timeout`,
  );
}

export async function buildBinary(
  root: string,
  backendDir: string,
  processes: Subprocess[],
): Promise<string> {
  const buildDir = join(root, "build");
  mkdirSync(buildDir, { mode: 0o700 });
  chmodSync(buildDir, 0o700);
  const binaryPath = join(
    buildDir,
    process.platform === "win32" ? "boxbox.exe" : "boxbox",
  );
  const env = sanitizedEnvironment();
  env.CGO_ENABLED = "0";
  const proc = spawn({
    cmd: [
      "go",
      "build",
      "-trimpath",
      "-ldflags=-s -w",
      "-o",
      binaryPath,
      "./cmd/server",
    ],
    cwd: backendDir,
    env,
    stdout: "ignore",
    stderr: "ignore",
  });
  processes.push(proc);
  const code = await proc.exited;
  if (code !== 0)
    throw new Error(`Go server build failed with exit status ${code}`);
  return binaryPath;
}
