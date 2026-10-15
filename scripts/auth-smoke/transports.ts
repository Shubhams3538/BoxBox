import { expectStatus } from "./assertions";
import { host, socketPath, streamPath } from "./constants";
import { request } from "./http";
import { type CredentialTransport } from "./types";
import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";
import { createConnection } from "node:net";

export async function privateDownload(
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

export async function expectWebSocketStatus(
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
