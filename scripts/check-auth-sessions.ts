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
import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { createServer as createNetServer, createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn, type Subprocess } from "bun";

const host = "127.0.0.1";
const username = "auth-smoke-user";
const mountName = "smoke";
const refreshCookieName = "boxbox_refresh";
const storeName = "auth-sessions.json";
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

let fixtureCredentials: { jwtSecret: string; passwordHash: string } | undefined;

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
function makeJwt(
  jwtSecret: string,
  tokenType: "access" | "refresh",
  sessionId: string | undefined,
): string {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(
    JSON.stringify({ alg: "HS256", typ: "JWT" }),
  ).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      user_id: createHash("sha256").update(username).digest("hex").slice(0, 16),
      username,
      token_type: tokenType,
      jti: randomUUID(),
      iss: "boxbox",
      sub: username,
      iat: now,
      nbf: now,
      exp: now + 3600,
      ...(sessionId === undefined ? {} : { sid: sessionId }),
    }),
  ).toString("base64url");
  const input = `${header}.${payload}`;
  const signature = createHmac("sha256", jwtSecret)
    .update(input)
    .digest("base64url");
  const token = `${input}.${signature}`;
  secrets.add(token);
  return token;
}

async function expectFailedLogin(
  baseUrl: string,
  password: string,
  existingRefreshToken: string,
  label: string,
): Promise<void> {
  const response = await request(baseUrl, label, `${apiRoot}/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: `${refreshCookieName}=${existingRefreshToken}`,
    },
    body: JSON.stringify({ username, password }),
  });
  expectStatus(response, 500, label);
  expectNoCookieChange(response, label);
  await expectNoPairResponse(response, label);
}

async function expectNoPairResponse(
  response: Response,
  label: string,
): Promise<void> {
  const body = await response.text();
  expect(
    !body.includes('"accessToken"') && !body.includes('"refreshToken"'),
    `${label}: failure returned a token pair`,
  );
}

function expectNoCookieChange(response: Response, label: string): void {
  expect(
    response.headers.get("set-cookie") === null,
    `${label}: retryable failure changed the refresh cookie`,
  );
}

async function withENOTDIR<T>(
  dataDir: string,
  backupDir: string,
  action: () => Promise<T>,
): Promise<T> {
  renameSync(dataDir, backupDir);
  try {
    writeFileSync(dataDir, "not-a-directory", { mode: 0o600 });
    return await action();
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
    renameSync(backupDir, dataDir);
  }
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
  refreshToken: string,
  label: string,
): Promise<Response> {
  return request(baseUrl, label, logoutPath, {
    method: "POST",
    headers: {
      Cookie: `${refreshCookieName}=${refreshToken}`,
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
  const env = sanitizedEnvironment();
  if (fixtureCredentials !== undefined) {
    env.BOXBOX_JWT_SECRET = fixtureCredentials.jwtSecret;
    env[`BOXBOX_USERS_${username}`] = fixtureCredentials.passwordHash;
  }
  const proc = spawn({
    cmd: [binaryPath, "-config", configPath],
    cwd: backendDir,
    env,
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
    throw new Error(`${label}: invalid session registry allowed startup`);
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
): string {
  const configPath = join(root, `${label}.yaml`);
  const config = [
    `port: ${port}`,
    `host: ${yamlString(host)}`,
    "rate_limit_rps: 1000",
    `data_dir: ${yamlString(dataDir)}`,
    "allowed_origins: []",
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

function writeStoreFixture(path: string, contents: string): void {
  writeFileSync(path, contents, { mode: 0o600 });
  chmodSync(path, 0o600);
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
  expect(storeInfo.isFile(), "active-session registry is not a regular file");
  expectMode(root, 0o700, "temporary root");
  expectMode(dataDir, 0o700, "auth data directory");
  expectMode(mountDir, 0o700, "private mount directory");
  expectMode(configPath, 0o600, "generated config");
  expectMode(markerPath, 0o600, "private marker file");
  expectMode(storePath, 0o600, "active-session registry");

  const configContents = readFileSync(configPath, "utf8");
  for (const credential of secrets) {
    if (credential && configContents.includes(credential)) {
      throw new Error(
        "generated authentication credential persisted to config",
      );
    }
  }

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

    fixtureCredentials = { jwtSecret, passwordHash };
    const dataDir = join(tempRoot, "durable-data");
    const configPath = writeConfig(
      tempRoot,
      "durable",
      port,
      dataDir,
      mountDir,
    );
    let server = await startServer(
      binaryPath,
      configPath,
      backendDir,
      port,
      processes,
      "initial server",
    );

    const logoutInitial = await login(
      baseUrl,
      password,
      issuedTokens,
      "session-wide logout login",
    );
    const logoutRotated = await refresh(
      baseUrl,
      logoutInitial.refreshToken,
      issuedTokens,
      "session-wide logout rotation",
    );
    const logoutRotatedAgain = await refresh(
      baseUrl,
      logoutRotated.refreshToken,
      issuedTokens,
      "second session-wide logout rotation",
    );
    const replayInitial = await login(
      baseUrl,
      password,
      issuedTokens,
      "concurrent refresh login",
    );
    const active = await login(baseUrl, password, issuedTokens, "active login");
    const independent = await login(
      baseUrl,
      password,
      issuedTokens,
      "independent login",
    );

    const concurrentRefreshes = await Promise.all(
      [1, 2].map(() =>
        request(baseUrl, "concurrent refresh replay", refreshPath, {
          method: "POST",
          headers: {
            Cookie: `${refreshCookieName}=${replayInitial.refreshToken}`,
          },
        }),
      ),
    );
    const winners = concurrentRefreshes.filter(
      (response) => response.status === 200,
    );
    const losers = concurrentRefreshes.filter(
      (response) => response.status === 401,
    );
    expect(winners.length === 1, "concurrent refresh did not have one winner");
    expect(losers.length === 1, "concurrent refresh did not reject one replay");
    const winnerResponse = winners[0];
    const loserResponse = losers[0];
    expect(
      winnerResponse !== undefined,
      "concurrent refresh winner was missing",
    );
    expect(
      loserResponse !== undefined,
      "concurrent refresh replay was missing",
    );
    expectCookieCleared(loserResponse, "concurrent refresh replay");
    await loserResponse.arrayBuffer();
    const replayWinner = {
      accessToken: await responseAccessToken(
        winnerResponse,
        "concurrent refresh winner",
      ),
      refreshToken: cookieValue(winnerResponse, "concurrent refresh winner"),
    };
    rememberPair(replayWinner, issuedTokens);
    const replayWinnerStillUsable = await refresh(
      baseUrl,
      replayWinner.refreshToken,
      issuedTokens,
      "refresh winner remains usable",
    );
    await protectedFiles(
      baseUrl,
      replayWinnerStillUsable.accessToken,
      200,
      "winner replacement access",
    );
    await expectRefreshRejected(
      baseUrl,
      replayInitial.refreshToken,
      "losing concurrent refresh replay",
    );
    const replayWinnerAfterReplay = await refresh(
      baseUrl,
      replayWinnerStillUsable.refreshToken,
      issuedTokens,
      "winner refresh after replay",
    );
    await protectedFiles(
      baseUrl,
      replayWinnerAfterReplay.accessToken,
      200,
      "winner access after replay",
    );

    await expectRefreshRejected(
      baseUrl,
      logoutInitial.refreshToken,
      "first rotated refresh before logout",
    );
    await expectRefreshRejected(
      baseUrl,
      logoutRotated.refreshToken,
      "second rotated refresh before logout",
    );
    const activeAccessTokens = [
      logoutInitial.accessToken,
      logoutRotated.accessToken,
      logoutRotatedAgain.accessToken,
    ];
    for (const [index, accessToken] of activeAccessTokens.entries()) {
      await protectedFiles(
        baseUrl,
        accessToken,
        200,
        `prior rotation access ${index + 1} before logout`,
      );
    }
    const logoutResponse = await logout(
      baseUrl,
      logoutRotatedAgain.refreshToken,
      "session-wide logout",
    );
    expectStatus(logoutResponse, 200, "session-wide logout");
    expectCookieCleared(logoutResponse, "session-wide logout");
    await logoutResponse.arrayBuffer();

    await killAndWait(server);
    server = await startServer(
      binaryPath,
      configPath,
      backendDir,
      port,
      processes,
      "durable session restart",
    );

    for (const [index, accessToken] of activeAccessTokens.entries()) {
      await protectedFiles(
        baseUrl,
        accessToken,
        401,
        `session-wide logged-out access ${index + 1} after restart`,
      );
    }
    await expectRefreshRejected(
      baseUrl,
      logoutRotatedAgain.refreshToken,
      "logged-out refresh after restart",
    );
    for (const [index, accessToken] of activeAccessTokens.entries()) {
      await privateDownload(
        baseUrl,
        accessToken,
        index === 0 ? "header" : "query",
        401,
        privateBytes,
        `logged-out private stream ${index + 1} after restart`,
      );
      await expectWebSocketStatus(
        port,
        accessToken,
        index === 0 ? "header" : "query",
        401,
        `logged-out WebSocket ${index === 0 ? "header" : "query"} after restart`,
      );
    }

    for (const { label, pair } of [
      { label: "active", pair: active },
      { label: "independent", pair: independent },
      { label: "concurrent-refresh winner", pair: replayWinnerAfterReplay },
    ]) {
      await protectedFiles(
        baseUrl,
        pair.accessToken,
        200,
        `${label} access after restart`,
      );
    }
    await expectRefreshRejected(
      baseUrl,
      replayInitial.refreshToken,
      "old concurrent refresh after restart",
    );
    const activeAfterRestart = await refresh(
      baseUrl,
      active.refreshToken,
      issuedTokens,
      "active refresh after restart",
    );
    const independentAfterRestart = await refresh(
      baseUrl,
      independent.refreshToken,
      issuedTokens,
      "independent refresh after restart",
    );
    const replayWinnerAfterRestart = await refresh(
      baseUrl,
      replayWinnerAfterReplay.refreshToken,
      issuedTokens,
      "winner refresh after restart replay",
    );
    await protectedFiles(
      baseUrl,
      activeAfterRestart.accessToken,
      200,
      "active replacement after restart",
    );
    await protectedFiles(
      baseUrl,
      independentAfterRestart.accessToken,
      200,
      "independent replacement after restart",
    );
    await protectedFiles(
      baseUrl,
      replayWinnerAfterRestart.accessToken,
      200,
      "replay winner replacement after restart",
    );
    await privateDownload(
      baseUrl,
      activeAfterRestart.accessToken,
      "header",
      200,
      privateBytes,
      "active stream bearer header after restart",
    );
    await privateDownload(
      baseUrl,
      independentAfterRestart.accessToken,
      "query",
      200,
      privateBytes,
      "independent stream token query after restart",
    );
    await expectWebSocketStatus(
      port,
      activeAfterRestart.accessToken,
      "header",
      101,
      "active WebSocket bearer header after restart",
    );
    await expectWebSocketStatus(
      port,
      independentAfterRestart.accessToken,
      "query",
      101,
      "independent WebSocket token query after restart",
    );

    const legacyAccess = makeJwt(jwtSecret, "access", undefined);
    const legacyRefresh = makeJwt(jwtSecret, "refresh", undefined);
    const unknownSessionId = randomUUID();
    const unknownSessionAccess = makeJwt(jwtSecret, "access", unknownSessionId);
    const unknownSessionRefresh = makeJwt(
      jwtSecret,
      "refresh",
      unknownSessionId,
    );
    await protectedFiles(
      baseUrl,
      legacyAccess,
      401,
      "legacy access without sid",
    );
    await expectRefreshRejected(
      baseUrl,
      legacyRefresh,
      "legacy refresh without sid",
    );
    await protectedFiles(
      baseUrl,
      unknownSessionAccess,
      401,
      "unknown session access",
    );
    await expectRefreshRejected(
      baseUrl,
      unknownSessionRefresh,
      "unknown session refresh",
    );
    issuedTokens.push(
      legacyAccess,
      legacyRefresh,
      unknownSessionAccess,
      unknownSessionRefresh,
    );

    results.push({
      scenario: "Legacy and unknown-session credentials",
      outcome: "PASS",
      evidence:
        "In-memory test-secret-signed legacy access/refresh JWTs without sid and access/refresh JWTs with an unregistered sid each returned HTTP 401 at the real API.",
    });

    results.push({
      scenario: "Session-wide logout, restart, and independent sessions",
      outcome: "PASS",
      evidence:
        "After SIGKILL/restart, all three access tokens from two prior rotations and the current refresh token from the logged-out sid returned 401; two separate logins and their refreshes remained HTTP 200.",
    });
    results.push({
      scenario: "Refresh replay and private transports",
      outcome: "PASS",
      evidence:
        "Two concurrent uses of one refresh token produced one HTTP 200 winner and one HTTP 401 replay; the winning session refreshed before and after restart. Active stream header/query returned exact marker bytes, active WebSocket header/query returned 101, and removed-session stream/WebSocket header/query returned 401.",
    });

    const obstructedDataDir = join(tempRoot, "durable-data-backup");
    await withENOTDIR(dataDir, obstructedDataDir, async () => {
      await expectFailedLogin(
        baseUrl,
        password,
        activeAfterRestart.refreshToken,
        "ENOTDIR login",
      );
    });
    const loginRetry = await login(
      baseUrl,
      password,
      issuedTokens,
      "login retry after storage restore",
    );
    await protectedFiles(
      baseUrl,
      loginRetry.accessToken,
      200,
      "retried login access",
    );
    const preservedCookieRetry = await refresh(
      baseUrl,
      activeAfterRestart.refreshToken,
      issuedTokens,
      "preexisting cookie retry after failed login",
    );
    await protectedFiles(
      baseUrl,
      preservedCookieRetry.accessToken,
      200,
      "preexisting cookie after failed login",
    );

    const retryable = await login(
      baseUrl,
      password,
      issuedTokens,
      "refresh storage retry login",
    );
    await withENOTDIR(dataDir, obstructedDataDir, async () => {
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
      expectNoCookieChange(failedRefresh, "ENOTDIR refresh");
      await expectNoPairResponse(failedRefresh, "ENOTDIR refresh");
      await protectedFiles(
        baseUrl,
        retryable.accessToken,
        200,
        "refresh failure preserved prior access",
      );
    });
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
      scenario: "ENOTDIR login and refresh retry",
      outcome: "PASS",
      evidence:
        "With durable-data replaced by a regular file, login and refresh each returned HTTP 500 without Set-Cookie; failed login returned no access pair, the sent auth cookie was not overwritten, the preexisting access remained HTTP 200, and login plus the identical refresh cookie succeeded after repair.",
    });

    const prior = await login(
      baseUrl,
      password,
      issuedTokens,
      "prior-session removal login",
    );
    const pending = await login(
      baseUrl,
      password,
      issuedTokens,
      "second-session logout retry login",
    );
    const priorLogout = await logout(
      baseUrl,
      prior.refreshToken,
      "prior-session logout",
    );
    expectStatus(priorLogout, 200, "prior-session logout");
    expectCookieCleared(priorLogout, "prior-session logout");
    await priorLogout.arrayBuffer();
    await protectedFiles(
      baseUrl,
      prior.accessToken,
      401,
      "prior access before failed second logout",
    );
    await expectRefreshRejected(
      baseUrl,
      prior.refreshToken,
      "prior refresh before failed second logout",
    );

    await withENOTDIR(dataDir, obstructedDataDir, async () => {
      const failedLogout = await logout(
        baseUrl,
        pending.refreshToken,
        "ENOTDIR logout",
      );
      expectStatus(failedLogout, 500, "ENOTDIR logout");
      expectNoCookieChange(failedLogout, "ENOTDIR logout");
      await expectNoPairResponse(failedLogout, "ENOTDIR logout");
    });
    await protectedFiles(
      baseUrl,
      prior.accessToken,
      401,
      "prior access after failed second logout",
    );
    await expectRefreshRejected(
      baseUrl,
      prior.refreshToken,
      "prior refresh after failed second logout",
    );
    await protectedFiles(
      baseUrl,
      pending.accessToken,
      200,
      "second-session access after failed logout",
    );
    const pendingLogoutRetry = await logout(
      baseUrl,
      pending.refreshToken,
      "second-session logout retry",
    );
    expectStatus(pendingLogoutRetry, 200, "second-session logout retry");
    expectCookieCleared(pendingLogoutRetry, "second-session logout retry");
    await pendingLogoutRetry.arrayBuffer();
    await protectedFiles(
      baseUrl,
      pending.accessToken,
      401,
      "second-session access after logout retry",
    );
    await expectRefreshRejected(
      baseUrl,
      pending.refreshToken,
      "second-session refresh after logout retry",
    );
    const laterWriteSession = await login(
      baseUrl,
      password,
      issuedTokens,
      "later session write after logout retry",
    );
    const laterWriteReplacement = await refresh(
      baseUrl,
      laterWriteSession.refreshToken,
      issuedTokens,
      "later session refresh write",
    );
    await protectedFiles(
      baseUrl,
      laterWriteReplacement.accessToken,
      200,
      "later session access after write",
    );
    await protectedFiles(
      baseUrl,
      prior.accessToken,
      401,
      "prior access after later session write",
    );
    await expectRefreshRejected(
      baseUrl,
      prior.refreshToken,
      "prior refresh after later session write",
    );

    await killAndWait(server);
    server = await startServer(
      binaryPath,
      configPath,
      backendDir,
      port,
      processes,
      "failure-retry restart",
    );
    await protectedFiles(
      baseUrl,
      prior.accessToken,
      401,
      "prior access after failure-retry restart",
    );
    await expectRefreshRejected(
      baseUrl,
      prior.refreshToken,
      "prior refresh after failure-retry restart",
    );
    await protectedFiles(
      baseUrl,
      pending.accessToken,
      401,
      "second-session access after logout restart",
    );
    await expectRefreshRejected(
      baseUrl,
      pending.refreshToken,
      "second-session refresh after logout restart",
    );
    await protectedFiles(
      baseUrl,
      laterWriteReplacement.accessToken,
      200,
      "later session access after failure-retry restart",
    );
    await protectedFiles(
      baseUrl,
      activeAfterRestart.accessToken,
      200,
      "unrelated session after failure-retry restart",
    );
    results.push({
      scenario: "ENOTDIR logout retry and prior removal preservation",
      outcome: "PASS",
      evidence:
        "ENOTDIR logout returned HTTP 500 without Set-Cookie or a token pair; retrying logout with the unchanged refresh cookie returned HTTP 200. The first session's removed access/refresh stayed HTTP 401 after the failed logout, a later login/refresh write, and SIGKILL/restart.",
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

    const storePath = join(dataDir, storeName);
    writeStoreFixture(storePath, "{malformed");
    await expectStartupRefusal(
      binaryPath,
      configPath,
      backendDir,
      port,
      processes,
      "malformed session store",
    );
    writeStoreFixture(storePath, JSON.stringify({ version: 2, sessions: {} }));
    await expectStartupRefusal(
      binaryPath,
      configPath,
      backendDir,
      port,
      processes,
      "future-version session store",
    );
    writeStoreFixture(storePath, JSON.stringify({ version: 1 }));
    await expectStartupRefusal(
      binaryPath,
      configPath,
      backendDir,
      port,
      processes,
      "missing sessions map",
    );
    writeStoreFixture(
      storePath,
      JSON.stringify({ version: 1, sessions: {}, unexpected: true }),
    );
    await expectStartupRefusal(
      binaryPath,
      configPath,
      backendDir,
      port,
      processes,
      "unknown session store field",
    );

    const symlinkTarget = join(tempRoot, "symlink-target.json");
    writeStoreFixture(
      symlinkTarget,
      JSON.stringify({ version: 1, sessions: {} }),
    );
    rmSync(storePath, { force: true });
    symlinkSync(symlinkTarget, storePath);
    await expectStartupRefusal(
      binaryPath,
      configPath,
      backendDir,
      port,
      processes,
      "symlink session store",
    );
    results.push({
      scenario: "Strict session-store startup validation",
      outcome: "PASS",
      evidence:
        "Malformed JSON, future version 2, missing required sessions map, unknown top-level field, and a symlink at auth-sessions.json each exited before /health became ready.",
    });

    const oldDataDir = join(tempRoot, "old-snapshot-data");
    const oldConfigPath = writeConfig(
      tempRoot,
      "old-snapshot",
      port,
      oldDataDir,
      mountDir,
    );
    server = await startServer(
      binaryPath,
      oldConfigPath,
      backendDir,
      port,
      processes,
      "old-snapshot limitation setup",
    );
    const oldSnapshotSession = await login(
      baseUrl,
      password,
      issuedTokens,
      "old-snapshot limitation login",
    );
    const oldSnapshot = join(tempRoot, "valid-old-snapshot.json");
    copyFileSync(join(oldDataDir, storeName), oldSnapshot);
    chmodSync(oldSnapshot, 0o600);
    const oldSnapshotLogout = await logout(
      baseUrl,
      oldSnapshotSession.refreshToken,
      "old-snapshot limitation logout",
    );
    expectStatus(oldSnapshotLogout, 200, "old-snapshot limitation logout");
    expectCookieCleared(oldSnapshotLogout, "old-snapshot limitation logout");
    await oldSnapshotLogout.arrayBuffer();
    await protectedFiles(
      baseUrl,
      oldSnapshotSession.accessToken,
      401,
      "session removed before old-snapshot restore",
    );
    await expectRefreshRejected(
      baseUrl,
      oldSnapshotSession.refreshToken,
      "refresh removed before old-snapshot restore",
    );
    await killAndWait(server);
    const oldSnapshotPath = join(oldDataDir, storeName);
    copyFileSync(oldSnapshot, oldSnapshotPath);
    chmodSync(oldSnapshotPath, 0o600);
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
      "access revived by valid prior session registry",
    );
    const revivedRefresh = await refresh(
      baseUrl,
      oldSnapshotSession.refreshToken,
      issuedTokens,
      "refresh revived by valid prior session registry",
    );
    await protectedFiles(
      baseUrl,
      revivedRefresh.accessToken,
      200,
      "replacement access after snapshot restore",
    );
    results.push({
      scenario: "LIMITATION: restoring an older valid session registry",
      outcome: "LIMITATION (expected risk)",
      evidence:
        "A backup captured while the sid was active restored both access validation (HTTP 200) and its current refresh (HTTP 200) after logout had removed it; rotate the JWT signing secret after restoring stale state to reject revived credentials.",
    });

    await killAndWait(server);
    const missingDataDir = join(tempRoot, "missing-session-store-data");
    const missingConfigPath = writeConfig(
      tempRoot,
      "missing-session-store",
      port,
      missingDataDir,
      mountDir,
    );
    server = await startServer(
      binaryPath,
      missingConfigPath,
      backendDir,
      port,
      processes,
      "missing session store setup",
    );
    const missingStoreSession = await login(
      baseUrl,
      password,
      issuedTokens,
      "missing-store session login",
    );
    const missingStorePath = join(missingDataDir, storeName);
    rmSync(missingStorePath, { force: true });
    await protectedFiles(
      baseUrl,
      missingStoreSession.accessToken,
      200,
      "loaded session remains active after store deletion",
    );
    results.push({
      scenario:
        "LIMITATION: runtime file deletion does not clear loaded sessions",
      outcome: "LIMITATION (expected risk)",
      evidence:
        "Deleting auth-sessions.json while the server was running left its already-loaded access token accepted with HTTP 200. File deletion is not immediate revocation; restart to discard loaded state.",
    });
    await killAndWait(server);
    server = await startServer(
      binaryPath,
      missingConfigPath,
      backendDir,
      port,
      processes,
      "missing session store restart",
    );
    await protectedFiles(
      baseUrl,
      missingStoreSession.accessToken,
      401,
      "old access after missing-store restart",
    );
    await expectRefreshRejected(
      baseUrl,
      missingStoreSession.refreshToken,
      "old refresh after missing-store restart",
    );
    const afterMissingStoreLogin = await login(
      baseUrl,
      password,
      issuedTokens,
      "fresh login after missing-store restart",
    );
    await protectedFiles(
      baseUrl,
      afterMissingStoreLogin.accessToken,
      200,
      "fresh access after missing-store restart",
    );

    await killAndWait(server);
    writeStoreFixture(
      missingStorePath,
      JSON.stringify({ version: 1, sessions: {} }),
    );
    server = await startServer(
      binaryPath,
      missingConfigPath,
      backendDir,
      port,
      processes,
      "empty session store restart",
    );
    await protectedFiles(
      baseUrl,
      missingStoreSession.accessToken,
      401,
      "old access after empty-store restart",
    );
    await expectRefreshRejected(
      baseUrl,
      missingStoreSession.refreshToken,
      "old refresh after empty-store restart",
    );
    await protectedFiles(
      baseUrl,
      afterMissingStoreLogin.accessToken,
      401,
      "previous fresh access after empty-store restart",
    );
    await expectRefreshRejected(
      baseUrl,
      afterMissingStoreLogin.refreshToken,
      "previous fresh refresh after empty-store restart",
    );
    const afterEmptyStoreLogin = await login(
      baseUrl,
      password,
      issuedTokens,
      "fresh login after empty-store restart",
    );
    await protectedFiles(
      baseUrl,
      afterEmptyStoreLogin.accessToken,
      200,
      "fresh access after empty-store restart",
    );
    results.push({
      scenario:
        "Missing file and valid empty registry fail closed after restart",
      outcome: "PASS",
      evidence:
        "After SIGKILL, a missing registry file denied old access and refresh with HTTP 401 while fresh login returned HTTP 200. Restarting with a valid empty v1 sessions map also denied both prior access/refresh pairs (HTTP 401) and allowed a fresh login (HTTP 200).",
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
    fixtureCredentials = undefined;
    secrets.clear();
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
