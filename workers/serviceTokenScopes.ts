// Scoping for Cloudflare Access service tokens.
//
// Human users (JWT with an email) keep full access, as before.
// Service tokens (JWT with `common_name` = Client ID and no email) only get what
// SERVICE_TOKEN_SCOPES grants them. Without that secret, every service token is denied.
//
// SERVICE_TOKEN_SCOPES (Worker secret, JSON):
//   {
//     "<client-id>.access": { "mailboxes": ["tec@csec.mx"], "methods": ["GET"] }
//   }

export interface ServiceTokenScope {
	mailboxes: string[];
	methods?: string[];
}

export type ScopeDecision = { allowed: true } | { allowed: false; reason: string };

const MAILBOX_PATH = /^\/api\/v1\/mailboxes\/([^/]+)(?:\/.*)?$/;

export function parseScopes(raw: string | undefined): Record<string, ServiceTokenScope> {
	if (!raw) return {};
	try {
		const parsed = JSON.parse(raw);
		return parsed && typeof parsed === "object" ? parsed : {};
	} catch {
		return {};
	}
}

export function isServiceToken(payload: Record<string, unknown>): boolean {
	return typeof payload.common_name === "string" && payload.common_name !== "" && !payload.email;
}

export function checkServiceTokenScope(
	payload: Record<string, unknown>,
	method: string,
	pathname: string,
	scopes: Record<string, ServiceTokenScope>,
): ScopeDecision {
	const clientId = String(payload.common_name ?? "");
	const scope = scopes[clientId];
	if (!scope) return { allowed: false, reason: "Service token has no scope" };

	const methods = (scope.methods ?? ["GET"]).map((m) => m.toUpperCase());
	if (!methods.includes(method.toUpperCase())) {
		return { allowed: false, reason: `Method ${method} not allowed for this service token` };
	}

	const match = MAILBOX_PATH.exec(pathname);
	if (!match) return { allowed: false, reason: "Service tokens may only use /api/v1/mailboxes/{mailbox}" };

	let mailbox: string;
	try {
		mailbox = decodeURIComponent(match[1]).toLowerCase();
	} catch {
		return { allowed: false, reason: "Invalid mailbox in path" };
	}
	const allowedMailboxes = (scope.mailboxes ?? []).map((m) => m.toLowerCase());
	if (!allowedMailboxes.includes(mailbox)) {
		return { allowed: false, reason: "Mailbox not allowed for this service token" };
	}
	return { allowed: true };
}
