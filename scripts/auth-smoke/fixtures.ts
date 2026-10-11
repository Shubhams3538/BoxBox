import { expect } from "./assertions";
import { host, mountName, storeName } from "./constants";
import { createCredentials, secrets } from "./credentials";
import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

export async function withENOTDIR<T>(
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

function yamlString(value: string): string {
  return JSON.stringify(value);
}

export function writeConfig(
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

export function writeStoreFixture(path: string, contents: string): void {
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

export function verifyPermissionsAndNoRawTokens(
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

export async function createFixture(tempRoot: string, port: number) {
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

  const { password, jwtSecret } = await createCredentials();
  const dataDir = join(tempRoot, "durable-data");
  const configPath = writeConfig(tempRoot, "durable", port, dataDir, mountDir);
  return {
    tempRoot,
    port,
    baseUrl,
    mountDir,
    markerPath,
    privateBytes,
    password,
    jwtSecret,
    dataDir,
    configPath,
  };
}

export type Fixture = Awaited<ReturnType<typeof createFixture>>;
