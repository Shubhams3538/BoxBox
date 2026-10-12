import { expectStatus } from "../assertions";
import { storeName } from "../constants";
import { type SmokeContext } from "../context";
import { writeConfig } from "../fixtures";
import {
  expectCookieCleared,
  expectRefreshRejected,
  login,
  logout,
  protectedFiles,
  refresh,
} from "../http";
import { killAndWait, startServer } from "../process";
import { chmodSync, copyFileSync } from "node:fs";
import { join } from "node:path";

export async function checkBackupRollback(context: SmokeContext) {
  const {
    tempRoot,
    port,
    baseUrl,
    mountDir,
    password,
    binaryPath,
    backendDir,
    processes,
    issuedTokens,
    results,
  } = context;
  const oldDataDir = join(tempRoot, "old-snapshot-data");
  const oldConfigPath = writeConfig(
    tempRoot,
    "old-snapshot",
    port,
    oldDataDir,
    mountDir,
  );
  let server = await startServer(
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
  return server;
}
