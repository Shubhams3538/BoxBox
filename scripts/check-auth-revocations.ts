#!/usr/bin/env bun

import {
  chmodSync,
  copyFileSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";
import { createServer as createNetServer, createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn, type Subprocess } from "bun";

const host = "127.0.0.1";
const username = "auth-smoke-user";
const mountName = "smoke";
const refreshCookieName = "boxbox_refresh";
const storeName = "auth-revocations.json";
const startupTimeoutMs = 20_000;
const apiRoot = "/api/v1";
const refreshPath = `${apiRoot}/auth/refresh`;
const logoutPath = `${apiRoot}/auth/logout`;
const streamPath = `${apiRoot}/stream/download/${mountName}/private-marker.txt`;
const socketPath = `${apiRoot}/ws`;

type TokenPair = { accessToken: string; refreshToken: string };
type Result = {
  scenario: string;
  outcome: "PASS" | "LIMITATION (expected risk)" | "FAIL";
  evidence: string;
};
type CliOptions =
  { kind: "help" } | { kind: "run"; binaryPath: string | undefined };
type StartupOutcome =
  { kind: "ready" } | { kind: "exited"; code: number } | { kind: "timeout" };
type CredentialTransport = "header" | "query";

const secrets = new Set<string>();

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
    "Usage: bun scripts/check-auth-revocations.ts [--binary /path/to/boxbox]\n" +
      "Without --binary, builds backend/cmd/server into a private temporary directory.",
  );
}

function sanitizedEnvironment(): Record<string, string> {
  const clean: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (
      value !== undefined &&
      !key.startsWith("BOXBOX_") &&
      !key.startsWith("FM_") &&
      key !== "CONFIG_PATH"
    ) {
      clean[key] = value;
    }
  }
  return clean;
}

function redactedMessage(error: unknown): string {
  let message =
    error instanceof Error ? error.message : "Unexpected smoke-check failure";
  for (const secret of secrets) {
    if (secret) message = message.replaceAll(secret, "[redacted]");
  }
  return message;
}

function expect(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function expectStatus(
  response: Response,
  expected: number,
  label: string,
): void {
  if (response.status !== expected) {
    throw new Error(
      `${label}: expected HTTP ${expected}, received HTTP ${response.status}`,
    );
  }
}

function expectCookieCleared(response: Response, label: string): void {
  const cookie = response.headers.get("set-cookie");
  const firstPart = cookie?.split(";", 1)[0];
  if (firstPart !== `${refreshCookieName}=`) {
    throw new Error(`${label}: expected the refresh cookie to be cleared`);
  }
}

function cookieValue(response: Response, label: string): string {
  const firstPart = response.headers.get("set-cookie")?.split(";", 1)[0];
  const prefix = `${refreshCookieName}=`;
  if (!firstPart?.startsWith(prefix) || firstPart.length === prefix.length) {
    throw new Error(`${label}: response did not set a refresh cookie`);
  }
  return firstPart.slice(prefix.length);
}

async function responseAccessToken(
  response: Response,
  label: string,
): Promise<string> {
  let payload: unknown;
  try {
    payload = JSON.parse(await response.text());
  } catch {
    throw new Error(`${label}: response was not valid JSON`);
  }
  if (
    typeof payload !== "object" ||
    payload === null ||
    !("accessToken" in payload) ||
    typeof payload.accessToken !== "string" ||
    payload.accessToken.length === 0
  ) {
    throw new Error(`${label}: response did not contain an access token`);
  }
  return payload.accessToken;
}

function rememberPair(pair: TokenPair, issuedTokens: string[]): void {
  issuedTokens.push(pair.accessToken, pair.refreshToken);
  secrets.add(pair.accessToken);
  secrets.add(pair.refreshToken);
}

async function request(
  baseUrl: string,
  label: string,
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("Connection", "close");
  try {
    return await fetch(`${baseUrl}${path}`, {
      ...init,
      headers,
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new Error(`${label}: HTTP request failed`);
  }
}

async function login(
  baseUrl: string,
  password: string,
  issuedTokens: string[],
  label: string,
): Promise<TokenPair> {
  const response = await request(baseUrl, label, `${apiRoot}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  expectStatus(response, 200, label);
  const pair = {
    accessToken: await responseAccessToken(response, label),
    refreshToken: cookieValue(response, label),
  };
  rememberPair(pair, issuedTokens);
  return pair;
}

async function refresh(
  baseUrl: string,
  refreshToken: string,
  issuedTokens: string[],
  label: string,
): Promise<TokenPair> {
  const response = await request(baseUrl, label, refreshPath, {
    method: "POST",
    headers: { Cookie: `${refreshCookieName}=${refreshToken}` },
  });
  expectStatus(response, 200, label);
  const pair = {
    accessToken: await responseAccessToken(response, label),
    refreshToken: cookieValue(response, label),
  };
  rememberPair(pair, issuedTokens);
  return pair;
}

async function expectRefreshRejected(
  baseUrl: string,
  refreshToken: string,
  label: string,
): Promise<void> {
  const response = await request(baseUrl, label, refreshPath, {
    method: "POST",
    headers: { Cookie: `${refreshCookieName}=${refreshToken}` },
  });
  expectStatus(response, 401, label);
  expectCookieCleared(response, label);
  await response.arrayBuffer();
}

async function logout(
  baseUrl: string,
  pair: TokenPair,
  label: string,
): Promise<Response> {
  return request(baseUrl, label, logoutPath, {
    method: "POST",
    headers: {
      Cookie: `${refreshCookieName}=${pair.refreshToken}`,
      Authorization: `Bearer ${pair.accessToken}`,
    },
  });
}

async function protectedFiles(
  baseUrl: string,
  accessToken: string,
  expectedStatus: number,
  label: string,
): Promise<void> {
  const response = await request(baseUrl, label, `${apiRoot}/files/`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  expectStatus(response, expectedStatus, label);
  await response.arrayBuffer();
}

async function privateDownload(
  baseUrl: string,
  accessToken: string,
  credential: CredentialTransport,
  expectedStatus: number,
  privateBytes: Buffer,
  label: string,
): Promise<void> {
  let path = streamPath;
  const headers = new Headers();
  if (credential === "header") {
    headers.set("Authorization", `Bearer ${accessToken}`);
  } else {
    path += `?${new URLSearchParams({ token: accessToken })}`;
  }

  const response = await request(baseUrl, label, path, { headers });
  expectStatus(response, expectedStatus, label);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (expectedStatus === 200 && !bytes.equals(privateBytes)) {
    throw new Error(
      `${label}: private download bytes did not match the marker file`,
    );
  }
  if (expectedStatus !== 200 && bytes.includes(privateBytes)) {
    throw new Error(
      `${label}: unauthorized response exposed the private marker bytes`,
    );
  }
}

function websocketHandshake(
  port: number,
  accessToken: string,
  credential: CredentialTransport,
): Promise<number> {
  const handshake = Promise.withResolvers<number>();
  const socket = createConnection({ host, port });
  let response = "";
  let settled = false;

  const finish = (status: number | undefined) => {
    if (settled) return;
    settled = true;
    socket.destroy();
    if (status === undefined) {
      handshake.reject(new Error("WebSocket handshake failed"));
    } else {
      handshake.resolve(status);
    }
  };

  socket.setTimeout(10_000, () => finish(undefined));
  socket.once("error", () => finish(undefined));
  socket.once("close", () => {
    if (!settled) finish(undefined);
  });
  socket.once("connect", () => {
    const path =
      credential === "query"
        ? `${socketPath}?token=${encodeURIComponent(accessToken)}`
        : socketPath;
    const key = randomBytes(16).toString("base64");
    const lines = [
      `GET ${path} HTTP/1.1`,
      `Host: ${host}:${port}`,
      "Upgrade: websocket",
      "Connection: Upgrade",
      `Sec-WebSocket-Key: ${key}`,
      "Sec-WebSocket-Version: 13",
    ];
    if (credential === "header")
      lines.push(`Authorization: Bearer ${accessToken}`);
    socket.write(`${lines.join("\r\n")}\r\n\r\n`);
  });
  socket.on("data", (chunk) => {
    if (settled) return;
    response += chunk.toString("latin1");
    const headerEnd = response.indexOf("\r\n\r\n");
    if (headerEnd === -1) {
      if (response.length > 16_384) finish(undefined);
      return;
    }
    const statusLine = response.slice(0, response.indexOf("\r\n"));
    const match = /^HTTP\/1\.[01] (\d{3})(?:\s|$)/.exec(statusLine);
    finish(match ? Number(match[1]) : undefined);
  });
  return handshake.promise;
}

async function expectWebSocketStatus(
  port: number,
  token: string,
  credential: CredentialTransport,
  expectedStatus: number,
  label: string,
): Promise<void> {
  const status = await websocketHandshake(port, token, credential);
  if (status !== expectedStatus) {
    throw new Error(
      `${label}: expected HTTP ${expectedStatus}, received HTTP ${status}`,
    );
  }
}

async function reservePort(): Promise<number> {
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
): Subprocess {
  const proc = spawn({
    cmd: [binaryPath, "-config", configPath],
    cwd: backendDir,
    env: sanitizedEnvironment(),
    stdout: "ignore",
    stderr: "ignore",
  });
  processes.push(proc);
  return proc;
}

async function killAndWait(proc: Subprocess): Promise<void> {
  if (proc.exitCode === null) {
    try {
      proc.kill("SIGKILL");
    } catch {
      // The process may have exited after the status check.
    }
  }
  await proc.exited;
}

async function startServer(
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

async function expectStartupRefusal(
  binaryPath: string,
  configPath: string,
  backendDir: string,
  port: number,
  processes: Subprocess[],
  label: string,
): Promise<void> {
  const proc = startProcess(binaryPath, configPath, backendDir, processes);
  const outcome = await observeStartup(proc, port);
  if (outcome.kind === "exited") {
    const code = await proc.exited;
    if (code !== 0) return;
    throw new Error(
      `${label}: server exited successfully instead of refusing startup`,
    );
  }
  if (outcome.kind === "ready") {
    await killAndWait(proc);
    throw new Error(`${label}: invalid revocation storage allowed startup`);
  }
  await killAndWait(proc);
  throw new Error(
    `${label}: server did not refuse startup before the readiness timeout`,
  );
}

async function buildBinary(
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

function yamlString(value: string): string {
  return JSON.stringify(value);
}

function writeConfig(
  root: string,
  label: string,
  port: number,
  dataDir: string,
  mountDir: string,
  jwtSecret: string,
  passwordHash: string,
): string {
  const configPath = join(root, `${label}.yaml`);
  const config = [
    `port: ${port}`,
    `host: ${yamlString(host)}`,
    `jwt_secret: ${yamlString(jwtSecret)}`,
    "rate_limit_rps: 1000",
    `data_dir: ${yamlString(dataDir)}`,
    "allowed_origins: []",
    "users:",
    `  ${yamlString(username)}: ${yamlString(passwordHash)}`,
    "mount_points:",
    `  - name: ${yamlString(mountName)}`,
    `    path: ${yamlString(mountDir)}`,
    "    read_only: true",
    "",
  ].join("\n");
  writeFileSync(configPath, config, { mode: 0o600 });
  chmodSync(configPath, 0o600);
  return configPath;
}

function expectMode(path: string, expected: number, label: string): void {
  const actual = statSync(path).mode & 0o777;
  if (actual !== expected) {
    throw new Error(
      `${label}: expected mode ${expected.toString(8)}, received ${actual.toString(8)}`,
    );
  }
}

function dataFiles(directory: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...dataFiles(path));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

function verifyPermissionsAndNoRawTokens(
  root: string,
  dataDir: string,
  configPath: string,
  mountDir: string,
  markerPath: string,
  issuedTokens: string[],
): void {
  const storePath = join(dataDir, storeName);
  const storeInfo = lstatSync(storePath);
  expect(storeInfo.isFile(), "revocation snapshot is not a regular file");
  expectMode(root, 0o700, "temporary root");
  expectMode(dataDir, 0o700, "auth data directory");
  expectMode(mountDir, 0o700, "private mount directory");
  expectMode(configPath, 0o600, "generated config");
  expectMode(markerPath, 0o600, "private marker file");
  expectMode(storePath, 0o600, "revocation snapshot");

  for (const path of dataFiles(dataDir)) {
    const contents = readFileSync(path, "utf8");
    if (issuedTokens.some((token) => contents.includes(token))) {
      throw new Error("auth data contains a raw JWT");
    }
  }
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

    tempRoot = mkdtempSync(join(tmpdir(), "boxbox-auth-revocations-"));
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

    const port = await reservePort();
    const baseUrl = `http://${host}:${port}`;
    const mountDir = join(tempRoot, "private-mount");
    mkdirSync(mountDir, { mode: 0o700 });
    chmodSync(mountDir, 0o700);
    const markerPath = join(mountDir, "private-marker.txt");
    const privateBytes = Buffer.from(
      `boxbox-auth-smoke-marker:${randomBytes(16).toString("hex")}\n`,
    );
    writeFileSync(markerPath, privateBytes, { mode: 0o600 });
    chmodSync(markerPath, 0o600);

    const password = randomBytes(32).toString("hex");
    secrets.add(password);
    const passwordHash = await Bun.password.hash(password, {
      algorithm: "bcrypt",
      cost: 10,
    });
    secrets.add(passwordHash);
    const jwtSecret = randomBytes(32).toString("hex");
    secrets.add(jwtSecret);

    const dataDir = join(tempRoot, "durable-data");
    const configPath = writeConfig(
      tempRoot,
      "durable",
      port,
      dataDir,
      mountDir,
      jwtSecret,
      passwordHash,
    );
    let server = await startServer(
      binaryPath,
      configPath,
      backendDir,
      port,
      processes,
      "initial server",
    );

    const revoked = await login(
      baseUrl,
      password,
      issuedTokens,
      "revocation login",
    );
    const active = await login(baseUrl, password, issuedTokens, "active login");
    const rotatedOriginal = await login(
      baseUrl,
      password,
      issuedTokens,
      "rotation login",
    );
    const replacement = await refresh(
      baseUrl,
      rotatedOriginal.refreshToken,
      issuedTokens,
      "initial refresh rotation",
    );

    await privateDownload(
      baseUrl,
      active.accessToken,
      "header",
      200,
      privateBytes,
      "active stream header",
    );
    await privateDownload(
      baseUrl,
      active.accessToken,
      "query",
      200,
      privateBytes,
      "active stream query",
    );
    await expectWebSocketStatus(
      port,
      active.accessToken,
      "header",
      101,
      "active WebSocket header handshake",
    );
    await expectWebSocketStatus(
      port,
      active.accessToken,
      "query",
      101,
      "active WebSocket query handshake",
    );

    const logoutResponse = await logout(baseUrl, revoked, "initial logout");
    expectStatus(logoutResponse, 200, "initial logout");
    expectCookieCleared(logoutResponse, "initial logout");
    await logoutResponse.arrayBuffer();

    await killAndWait(server);
    server = await startServer(
      binaryPath,
      configPath,
      backendDir,
      port,
      processes,
      "durable restart",
    );

    await protectedFiles(
      baseUrl,
      revoked.accessToken,
      401,
      "revoked access after restart",
    );
    await expectRefreshRejected(
      baseUrl,
      revoked.refreshToken,
      "revoked refresh after restart",
    );
    await privateDownload(
      baseUrl,
      revoked.accessToken,
      "header",
      401,
      privateBytes,
      "revoked stream header after restart",
    );
    await privateDownload(
      baseUrl,
      revoked.accessToken,
      "query",
      401,
      privateBytes,
      "revoked stream query after restart",
    );
    await expectWebSocketStatus(
      port,
      revoked.accessToken,
      "header",
      401,
      "revoked WebSocket header handshake",
    );
    await expectWebSocketStatus(
      port,
      revoked.accessToken,
      "query",
      401,
      "revoked WebSocket query handshake",
    );

    await protectedFiles(
      baseUrl,
      active.accessToken,
      200,
      "unaffected active access after restart",
    );
    await protectedFiles(
      baseUrl,
      replacement.accessToken,
      200,
      "replacement access after restart",
    );
    await expectRefreshRejected(
      baseUrl,
      rotatedOriginal.refreshToken,
      "rotated refresh replay after restart",
    );
    await protectedFiles(
      baseUrl,
      active.accessToken,
      200,
      "active access after old replay",
    );
    const activeAfterReplay = await refresh(
      baseUrl,
      active.refreshToken,
      issuedTokens,
      "active refresh after old replay",
    );
    await protectedFiles(
      baseUrl,
      activeAfterReplay.accessToken,
      200,
      "active replacement after old replay",
    );
    await protectedFiles(
      baseUrl,
      replacement.accessToken,
      200,
      "replacement access after old replay",
    );
    const replacementAfterReplay = await refresh(
      baseUrl,
      replacement.refreshToken,
      issuedTokens,
      "replacement refresh after old replay",
    );
    await expectRefreshRejected(
      baseUrl,
      rotatedOriginal.refreshToken,
      "repeated old refresh replay",
    );
    await protectedFiles(
      baseUrl,
      replacementAfterReplay.accessToken,
      200,
      "new replacement access after old replay",
    );
    await privateDownload(
      baseUrl,
      active.accessToken,
      "header",
      200,
      privateBytes,
      "active stream header after restart",
    );
    await privateDownload(
      baseUrl,
      replacementAfterReplay.accessToken,
      "query",
      200,
      privateBytes,
      "replacement stream query after restart",
    );
    await expectWebSocketStatus(
      port,
      active.accessToken,
      "header",
      101,
      "active WebSocket header after restart",
    );
    await expectWebSocketStatus(
      port,
      replacementAfterReplay.accessToken,
      "query",
      101,
      "replacement WebSocket query after restart",
    );
    results.push({
      scenario: "Restart, rotation, and old-token replay",
      outcome: "PASS",
      evidence:
        "Logout-revoked access/refresh and rotated refresh stayed rejected after SIGKILL/restart; active and replacement sessions continued refreshing after old-token replay.",
    });
    results.push({
      scenario: "Protected stream and WebSocket transports",
      outcome: "PASS",
      evidence:
        "Private stream bytes matched exactly for bearer-header and token-query requests; fresh WebSocket header/query handshakes accepted active tokens and rejected revoked access.",
    });

    const retryable = await login(
      baseUrl,
      password,
      issuedTokens,
      "storage retry login",
    );
    const obstructedDataDir = join(tempRoot, "durable-data-backup");
    renameSync(dataDir, obstructedDataDir);
    try {
      writeFileSync(dataDir, "not-a-directory", { mode: 0o600 });
      const failedRefresh = await request(
        baseUrl,
        "ENOTDIR refresh",
        refreshPath,
        {
          method: "POST",
          headers: { Cookie: `${refreshCookieName}=${retryable.refreshToken}` },
        },
      );
      expectStatus(failedRefresh, 500, "ENOTDIR refresh");
      expect(
        failedRefresh.headers.get("set-cookie") === null,
        "ENOTDIR refresh: retryable failure changed the refresh cookie",
      );
      await failedRefresh.arrayBuffer();
    } finally {
      rmSync(dataDir, { force: true });
      renameSync(obstructedDataDir, dataDir);
    }
    const retried = await refresh(
      baseUrl,
      retryable.refreshToken,
      issuedTokens,
      "refresh retry after storage restore",
    );
    await protectedFiles(
      baseUrl,
      retried.accessToken,
      200,
      "retried replacement access",
    );
    results.push({
      scenario: "Pre-publication ENOTDIR failure and retry",
      outcome: "PASS",
      evidence:
        "A regular-file obstruction forced ENOTDIR; refresh returned 500 without Set-Cookie, and the identical cookie rotated successfully after the directory was restored.",
    });

    const prior = await login(
      baseUrl,
      password,
      issuedTokens,
      "prior-revocation login",
    );
    const pending = await login(
      baseUrl,
      password,
      issuedTokens,
      "mixed-session login",
    );
    const priorLogout = await logout(baseUrl, prior, "prior-revocation logout");
    expectStatus(priorLogout, 200, "prior-revocation logout");
    expectCookieCleared(priorLogout, "prior-revocation logout");
    await priorLogout.arrayBuffer();
    await protectedFiles(
      baseUrl,
      prior.accessToken,
      401,
      "prior access before mixed logout",
    );
    await expectRefreshRejected(
      baseUrl,
      prior.refreshToken,
      "prior refresh before mixed logout",
    );

    renameSync(dataDir, obstructedDataDir);
    try {
      writeFileSync(dataDir, "not-a-directory", { mode: 0o600 });
      const failedLogout = await request(
        baseUrl,
        "mixed-session ENOTDIR logout",
        logoutPath,
        {
          method: "POST",
          headers: {
            Cookie: `${refreshCookieName}=${pending.refreshToken}`,
            Authorization: `Bearer ${prior.accessToken}`,
          },
        },
      );
      expectStatus(failedLogout, 500, "mixed-session ENOTDIR logout");
      expect(
        failedLogout.headers.get("set-cookie") === null,
        "mixed-session logout: retryable failure changed the refresh cookie",
      );
      await failedLogout.arrayBuffer();
    } finally {
      rmSync(dataDir, { force: true });
      renameSync(obstructedDataDir, dataDir);
    }
    await protectedFiles(
      baseUrl,
      prior.accessToken,
      401,
      "prior access revocation after failed mixed logout",
    );
    await expectRefreshRejected(
      baseUrl,
      prior.refreshToken,
      "prior refresh revocation after failed mixed logout",
    );
    const pendingRetry = await refresh(
      baseUrl,
      pending.refreshToken,
      issuedTokens,
      "new session retry after mixed logout failure",
    );
    await protectedFiles(
      baseUrl,
      pendingRetry.accessToken,
      200,
      "new session access after mixed logout failure",
    );

    await killAndWait(server);
    server = await startServer(
      binaryPath,
      configPath,
      backendDir,
      port,
      processes,
      "mixed-session rollback restart",
    );
    await protectedFiles(
      baseUrl,
      prior.accessToken,
      401,
      "prior access after mixed-session restart",
    );
    await protectedFiles(
      baseUrl,
      pendingRetry.accessToken,
      200,
      "replacement access after mixed-session restart",
    );

    results.push({
      scenario: "Mixed-session pre-publication rollback",
      outcome: "PASS",
      evidence:
        "Failed logout of a second session preserved the first session's already-persisted access/refresh revocation and left the second refresh usable after restart.",
    });

    verifyPermissionsAndNoRawTokens(
      tempRoot,
      dataDir,
      configPath,
      mountDir,
      markerPath,
      issuedTokens,
    );
    results.push({
      scenario: "Filesystem permissions and token-at-rest check",
      outcome: "PASS",
      evidence:
        "Temporary/data/mount directories were 0700, generated config/marker/snapshot were 0600, and no issued raw JWT appeared in auth data files.",
    });

    await killAndWait(server);
    server = await startServer(
      binaryPath,
      configPath,
      backendDir,
      port,
      processes,
      "corrupt-store setup restart",
    );
    await killAndWait(server);

    const storePath = join(dataDir, storeName);
    writeFileSync(storePath, "{malformed", { mode: 0o600 });
    chmodSync(storePath, 0o600);
    await expectStartupRefusal(
      binaryPath,
      configPath,
      backendDir,
      port,
      processes,
      "malformed revocation snapshot",
    );

    writeFileSync(
      storePath,
      JSON.stringify({ version: 999, revokedRefresh: {}, revokedAccess: {} }),
      { mode: 0o600 },
    );
    chmodSync(storePath, 0o600);
    await expectStartupRefusal(
      binaryPath,
      configPath,
      backendDir,
      port,
      processes,
      "future-version revocation snapshot",
    );

    const symlinkTarget = join(tempRoot, "symlink-target.json");
    writeFileSync(
      symlinkTarget,
      JSON.stringify({ version: 1, revokedRefresh: {}, revokedAccess: {} }),
      { mode: 0o600 },
    );
    chmodSync(symlinkTarget, 0o600);
    rmSync(storePath, { force: true });
    symlinkSync(symlinkTarget, storePath);
    await expectStartupRefusal(
      binaryPath,
      configPath,
      backendDir,
      port,
      processes,
      "symlink revocation snapshot",
    );
    results.push({
      scenario: "Strict startup validation",
      outcome: "PASS",
      evidence:
        "Malformed JSON, an unsupported future version, and a symlink snapshot each terminated startup before the health endpoint became ready.",
    });

    const oldDataDir = join(tempRoot, "old-snapshot-data");
    const oldConfigPath = writeConfig(
      tempRoot,
      "old-snapshot",
      port,
      oldDataDir,
      mountDir,
      jwtSecret,
      passwordHash,
    );
    server = await startServer(
      binaryPath,
      oldConfigPath,
      backendDir,
      port,
      processes,
      "old-snapshot limitation setup",
    );
    const oldSnapshot = join(tempRoot, "valid-old-snapshot.json");
    copyFileSync(join(oldDataDir, storeName), oldSnapshot);
    chmodSync(oldSnapshot, 0o600);
    const oldSnapshotSession = await login(
      baseUrl,
      password,
      issuedTokens,
      "old-snapshot limitation login",
    );
    const oldSnapshotLogout = await logout(
      baseUrl,
      oldSnapshotSession,
      "old-snapshot limitation logout",
    );
    expectStatus(oldSnapshotLogout, 200, "old-snapshot limitation logout");
    await oldSnapshotLogout.arrayBuffer();
    await protectedFiles(
      baseUrl,
      oldSnapshotSession.accessToken,
      401,
      "revocation before old-snapshot restore",
    );
    await killAndWait(server);
    copyFileSync(oldSnapshot, join(oldDataDir, storeName));
    chmodSync(join(oldDataDir, storeName), 0o600);
    server = await startServer(
      binaryPath,
      oldConfigPath,
      backendDir,
      port,
      processes,
      "valid old-snapshot restart",
    );
    await protectedFiles(
      baseUrl,
      oldSnapshotSession.accessToken,
      200,
      "credential revived by valid old snapshot",
    );
    await refresh(
      baseUrl,
      oldSnapshotSession.refreshToken,
      issuedTokens,
      "refresh revived by valid old snapshot",
    );
    results.push({
      scenario: "Known limitation: restoring an older valid snapshot",
      outcome: "LIMITATION (expected risk)",
      evidence:
        "Restoring a valid prior snapshot revived a credential revoked in the newer snapshot; backup rollback requires JWT signing-secret rotation.",
    });

    await killAndWait(server);
    const missingDataDir = join(tempRoot, "missing-snapshot-data");
    const missingConfigPath = writeConfig(
      tempRoot,
      "missing-snapshot",
      port,
      missingDataDir,
      mountDir,
      jwtSecret,
      passwordHash,
    );
    server = await startServer(
      binaryPath,
      missingConfigPath,
      backendDir,
      port,
      processes,
      "missing-snapshot limitation setup",
    );
    const missingSession = await login(
      baseUrl,
      password,
      issuedTokens,
      "missing-snapshot limitation login",
    );
    const missingLogout = await logout(
      baseUrl,
      missingSession,
      "missing-snapshot limitation logout",
    );
    expectStatus(missingLogout, 200, "missing-snapshot limitation logout");
    await missingLogout.arrayBuffer();
    await protectedFiles(
      baseUrl,
      missingSession.accessToken,
      401,
      "revocation before snapshot deletion",
    );
    await killAndWait(server);
    rmSync(join(missingDataDir, storeName), { force: true });
    server = await startServer(
      binaryPath,
      missingConfigPath,
      backendDir,
      port,
      processes,
      "missing-snapshot restart",
    );
    await protectedFiles(
      baseUrl,
      missingSession.accessToken,
      200,
      "credential revived by missing snapshot",
    );
    await refresh(
      baseUrl,
      missingSession.refreshToken,
      issuedTokens,
      "refresh revived by missing snapshot",
    );
    results.push({
      scenario: "Known limitation: deleted/missing snapshot",
      outcome: "LIMITATION (expected risk)",
      evidence:
        "Deleting the snapshot caused first-run initialization and revived previously revoked credentials; snapshot loss requires JWT signing-secret rotation.",
    });
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
    process.removeListener("SIGTERM", onInterrupt);
  }
  if (interrupted && !failure) failure = "Interrupted before completion";

  if (failure && !results.some((result) => result.outcome === "FAIL")) {
    results.push({ scenario: "Cleanup", outcome: "FAIL", evidence: failure });
  }
  printResults(results);
  if (failure) {
    console.error(`Auth revocation smoke check failed: ${failure}`);
    process.exitCode = 1;
  }
}

await runSmoke();
