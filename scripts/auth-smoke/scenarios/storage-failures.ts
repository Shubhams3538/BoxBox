import { expectStatus } from "../assertions";
import { refreshCookieName, refreshPath } from "../constants";
import { type SmokeContext } from "../context";
import { verifyPermissionsAndNoRawTokens, withENOTDIR } from "../fixtures";
import {
  expectCookieCleared,
  expectFailedLogin,
  expectNoCookieChange,
  expectNoPairResponse,
  expectRefreshRejected,
  login,
  logout,
  protectedFiles,
  refresh,
  request,
} from "../http";
import { killAndWait, startServer } from "../process";
import { type TokenPair } from "../types";
import { type Subprocess } from "bun";
import { join } from "node:path";

export async function checkStorageFailures(
  context: SmokeContext,
  server: Subprocess,
  activeAfterRestart: TokenPair,
) {
  const {
    tempRoot,
    port,
    baseUrl,
    mountDir,
    markerPath,
    password,
    dataDir,
    configPath,
    binaryPath,
    backendDir,
    processes,
    issuedTokens,
    results,
  } = context;
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
  return server;
}
