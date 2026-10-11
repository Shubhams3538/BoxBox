import { storeName } from "../constants";
import { type SmokeContext } from "../context";
import { writeConfig, writeStoreFixture } from "../fixtures";
import { expectRefreshRejected, login, protectedFiles } from "../http";
import { killAndWait, startServer } from "../process";
import { type Subprocess } from "bun";
import { rmSync } from "node:fs";
import { join } from "node:path";

export async function checkMissingStore(
  context: SmokeContext,
  server: Subprocess,
) {
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
    scenario: "Missing file and valid empty registry fail closed after restart",
    outcome: "PASS",
    evidence:
      "After SIGKILL, a missing registry file denied old access and refresh with HTTP 401 while fresh login returned HTTP 200. Restarting with a valid empty v1 sessions map also denied both prior access/refresh pairs (HTTP 401) and allowed a fresh login (HTTP 200).",
  });
}
