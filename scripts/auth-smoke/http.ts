import { expect, expectStatus } from "./assertions";
import {
  apiRoot,
  logoutPath,
  refreshCookieName,
  refreshPath,
  username,
} from "./constants";
import { rememberPair } from "./credentials";
import { type TokenPair } from "./types";

export function expectCookieCleared(response: Response, label: string): void {
  const cookie = response.headers.get("set-cookie");
  const firstPart = cookie?.split(";", 1)[0];
  if (firstPart !== `${refreshCookieName}=`) {
    throw new Error(`${label}: expected the refresh cookie to be cleared`);
  }
}

export function cookieValue(response: Response, label: string): string {
  const firstPart = response.headers.get("set-cookie")?.split(";", 1)[0];
  const prefix = `${refreshCookieName}=`;
  if (!firstPart?.startsWith(prefix) || firstPart.length === prefix.length) {
    throw new Error(`${label}: response did not set a refresh cookie`);
  }
  return firstPart.slice(prefix.length);
}

export async function responseAccessToken(
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

export async function expectFailedLogin(
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

export async function expectNoPairResponse(
  response: Response,
  label: string,
): Promise<void> {
  const body = await response.text();
  expect(
    !body.includes('"accessToken"') && !body.includes('"refreshToken"'),
    `${label}: failure returned a token pair`,
  );
}

export function expectNoCookieChange(response: Response, label: string): void {
  expect(
    response.headers.get("set-cookie") === null,
    `${label}: retryable failure changed the refresh cookie`,
  );
}

export async function request(
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

export async function login(
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

export async function refresh(
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

export async function expectRefreshRejected(
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

export async function expectRefreshSuperseded(
  baseUrl: string,
  refreshToken: string,
  label: string,
): Promise<void> {
  const response = await request(baseUrl, label, refreshPath, {
    method: "POST",
    headers: { Cookie: `${refreshCookieName}=${refreshToken}` },
  });
  expectStatus(response, 409, label);
  if (response.headers.has("Set-Cookie"))
    throw new Error(`${label}: stale request changed the cookie`);
  const body: unknown = await response.json();
  if (
    typeof body !== "object" ||
    body === null ||
    !("code" in body) ||
    body.code !== "REFRESH_SUPERSEDED"
  )
    throw new Error(`${label}: missing conflict code`);
}

export async function logout(
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

export async function protectedFiles(
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
