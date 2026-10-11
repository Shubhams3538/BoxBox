/**
 * Auth API module for authentication operations
 */

import {
	apiRequest,
	setAccessToken,
	refreshSession,
	logoutSession,
	isAuthenticated as checkAuth,
	type AccessTokenResponse
} from './client';
import { earlyStart, type EarlyStartSource } from './earlyStart';

/**
 * Login request
 */
export interface LoginRequest {
	username: string;
	password: string;
}

/**
 * Login response
 */
export type LoginResponse = AccessTokenResponse;

/**
 * Login with username and password
 * POST /api/v1/auth/login
 */
export async function login(username: string, password: string): Promise<LoginResponse> {
	const body: LoginRequest = { username, password };

	const response = await apiRequest<LoginResponse>('/auth/login', {
		method: 'POST',
		body,
		skipAuth: true
	});

	// Store tokens on successful login
	setAccessToken(response.accessToken);

	return response;
}

/**
 * Refresh access token using refresh token
 * POST /api/v1/auth/refresh
 */
export function refresh(): Promise<LoginResponse> {
	return refreshSession();
}

/**
 * Restore the session when the page loads. Uses the refresh the page shell already started, if it
 * did, and asks the server otherwise. Never both: each refresh rotates the refresh token. A 401 from
 * the shell's refresh is final, so a logged-out visit makes one refresh request, not two.
 */
export async function restoreSession(
	source: EarlyStartSource = earlyStart
): Promise<LoginResponse> {
	const early = await source.takeSession();
	if (early === 'rejected') throw new Error('No valid session');
	if (!early) return refresh();
	setAccessToken(early.accessToken);
	return early;
}

/**
 * Logout and invalidate refresh token
 * POST /api/v1/auth/logout
 */
export function logout(): Promise<void> {
	return logoutSession();
}

/**
 * Check if user is currently authenticated
 */
export function isAuthenticated(): boolean {
	return checkAuth();
}

// Re-export token utilities for convenience
export { getAccessToken, clearTokens } from './client';
