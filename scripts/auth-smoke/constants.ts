export const host = "127.0.0.1";

export const username = "auth-smoke-user";

export const mountName = "smoke";

export const refreshCookieName = "boxbox_refresh";

export const storeName = "auth-sessions.json";

export const startupTimeoutMs = 20_000;

export const apiRoot = "/api/v1";

export const refreshPath = `${apiRoot}/auth/refresh`;

export const logoutPath = `${apiRoot}/auth/logout`;

export const streamPath = `${apiRoot}/stream/download/${mountName}/private-marker.txt`;

export const socketPath = `${apiRoot}/ws`;
