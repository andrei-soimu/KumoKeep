// Minimal client for the KumoKeep API (see api/openapi.yaml).

export type User = {
	id: string;
	username: string;
	email: string;
	role: 'admin' | 'user';
	created_at: string;
};

export class ApiError extends Error {
	constructor(
		public status: number,
		public code: string,
		message: string
	) {
		super(message);
	}
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
	const res = await fetch(`/api/v1${path}`, {
		method,
		credentials: 'same-origin',
		headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
		body: body === undefined ? undefined : JSON.stringify(body)
	});
	if (res.status === 204) return undefined as T;
	const data = await res.json().catch(() => ({}));
	if (!res.ok) {
		throw new ApiError(res.status, data.error ?? 'unknown', data.message ?? res.statusText);
	}
	return data as T;
}

export const api = {
	me: () => request<User>('GET', '/me'),
	login: (login: string, password: string) =>
		request<User>('POST', '/auth/login', { login, password }),
	logout: () => request<void>('POST', '/auth/logout'),
	register: (invite: string, username: string, email: string, password: string) =>
		request<User>('POST', '/auth/register', { invite, username, email, password })
};
