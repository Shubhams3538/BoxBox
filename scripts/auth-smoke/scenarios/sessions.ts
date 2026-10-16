import { expect, expectStatus } from "../assertions";
import { refreshCookieName, refreshPath } from "../constants";
import { type SmokeContext } from "../context";
import { makeJwt, rememberPair } from "../credentials";
import {
  cookieValue,
  expectCookieCleared,
  expectRefreshRejected,
  expectRefreshSuperseded,
  login,
  logout,
  protectedFiles,
  refresh,
  request,
  responseAccessToken,
} from "../http";
import { killAndWait, startServer } from "../process";
import { expectWebSocketStatus, privateDownload } from "../transports";
import { type Subprocess } from "bun";
import { randomUUID } from "node:crypto";

export async function checkSessions(context: SmokeContext, server: Subprocess) {
  const {
    port,
    baseUrl,
    privateBytes,
    password,
    jwtSecret,
    configPath,
    binaryPath,
    backendDir,
    processes,
    issuedTokens,
    results,
  } = context;
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
    (response) => response.status === 409,
  );
  expect(winners.length === 1, "concurrent refresh did not have one winner");
  expect(losers.length === 1, "concurrent refresh did not reject one replay");
  const winnerResponse = winners[0];
  const loserResponse = losers[0];
  expect(winnerResponse !== undefined, "concurrent refresh winner was missing");
  expect(loserResponse !== undefined, "concurrent refresh replay was missing");
  expect(
    !loserResponse.headers.has("Set-Cookie"),
    "concurrent refresh replay changed the shared cookie",
  );
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
  await expectRefreshSuperseded(
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

  await expectRefreshSuperseded(
    baseUrl,
    logoutInitial.refreshToken,
    "first rotated refresh before logout",
  );
  await expectRefreshSuperseded(
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
  await expectRefreshSuperseded(
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
  const unknownSessionRefresh = makeJwt(jwtSecret, "refresh", unknownSessionId);
  await protectedFiles(baseUrl, legacyAccess, 401, "legacy access without sid");
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
      "Two concurrent uses of one refresh token produced one HTTP 200 winner and one HTTP 409 replay without Set-Cookie; the winning session refreshed before and after restart. Active stream header/query returned exact marker bytes, active WebSocket header/query returned 101, and removed-session stream/WebSocket header/query returned 401.",
  });
  return { server, activeAfterRestart };
}
