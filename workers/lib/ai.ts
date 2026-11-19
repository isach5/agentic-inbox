// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * AI-powered email security and quality tools.
 *
 * - isPromptInjection: scans email bodies for malicious prompt injection.
 * - verifyDraft: reviews draft email bodies and removes agent/system artifacts.
 */

// Workers AI desactivado (SH-117, costo). Estas funciones ya no llaman a ningún
// modelo: verifyDraft devuelve el cuerpo tal cual (sin borrarlo) e
// isPromptInjection siempre bloquea, por si algo vuelve a llamarla.

export async function isPromptInjection(_bodyHtml?: string | null): Promise<boolean> {
	return true;
}

export async function verifyDraft(body: string): Promise<string> {
	return body;
}
