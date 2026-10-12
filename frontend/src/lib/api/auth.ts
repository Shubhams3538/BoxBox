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
