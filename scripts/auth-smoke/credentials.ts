import { username } from "./constants";
import { type TokenPair } from "./types";
import { Buffer } from "node:buffer";
import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";

export const secrets = new Set<string>();

export let fixtureCredentials:
  { jwtSecret: string; passwordHash: string } | undefined;

export function sanitizedEnvironment(): Record<string, string> {
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

export function redactedMessage(error: unknown): string {
  let message =
    error instanceof Error ? error.message : "Unexpected smoke-check failure";
  for (const secret of secrets) {
    if (secret) message = message.replaceAll(secret, "[redacted]");
  }
  return message;
}

export function makeJwt(
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

export function rememberPair(pair: TokenPair, issuedTokens: string[]): void {
  issuedTokens.push(pair.accessToken, pair.refreshToken);
  secrets.add(pair.accessToken);
  secrets.add(pair.refreshToken);
}

export async function createCredentials() {
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
  return { password, jwtSecret };
}

export function clearCredentials(): void {
  fixtureCredentials = undefined;
  secrets.clear();
}
