// Fetch guard: prevents the Authorization header from being sent to
// restricted hosts (see NO_AUTH_HOSTS).
//
// Usage: every request routed through the patched window.fetch passes its
// arguments through guardFetchArgs(), which rewrites them (only when needed)
// so that the request goes out without an Authorization header.

const NO_AUTH_HOSTS = ['chat.i7i.ch'];

const resolveUrl = (input: RequestInfo | URL): URL => {
	if (typeof input === 'string') {
		return new URL(input, window.location.origin);
	}
	if (input instanceof URL) {
		return input;
	}
	return new URL(input.url, window.location.origin);
};

export const isNoAuthUrl = (input: RequestInfo | URL): boolean => {
	try {
		const url = resolveUrl(input);
		return url.protocol === 'https:' && NO_AUTH_HOSTS.includes(url.hostname);
	} catch {
		return false;
	}
};

const hasAuthHeader = (headers: Headers): boolean =>
	[...headers.keys()].some((k) => k.toLowerCase() === 'authorization');

/**
 * Returns possibly-rewritten [input, init] with the Authorization header
 * removed when the target host matches NO_AUTH_HOSTS. Arguments are returned
 * unchanged for all other requests (zero overhead beyond a URL check).
 */
export const guardFetchArgs = (
	input: RequestInfo | URL,
	init?: RequestInit
): [RequestInfo | URL, RequestInit | undefined] => {
	if (!isNoAuthUrl(input)) return [input, init];

	// Case 1: Request object -> headers live on the Request itself and are
	// immutable with it, so rebuild a new Request without the header.
	if (input instanceof Request) {
		if (!hasAuthHeader(input.headers)) return [input, init];
		const headers = new Headers(input.headers);
		headers.delete('Authorization');
		return [new Request(input, { headers }), init];
	}

	// Case 2: (input, init) form -> strip from init.headers if present.
	if (init?.headers) {
		const headers = new Headers(init.headers);
		if (!headers.has('Authorization')) return [input, init];
		headers.delete('Authorization');
		return [input, { ...init, headers }];
	}

	return [input, init];
};
