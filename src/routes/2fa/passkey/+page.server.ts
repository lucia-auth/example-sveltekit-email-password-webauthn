import { redirect } from "@sveltejs/kit";
import { get2FARedirect } from "$lib/server/2fa";
import { getUserPasskeyCredentials } from "$lib/server/webauthn";

import type { RequestEvent } from "./$types";

export async function load(event: RequestEvent) {
	if (event.locals.session === null || event.locals.user === null) {
		return redirect(302, "/login");
	}
	if (!event.locals.user.emailVerified) {
		return redirect(302, "/verify-email");
	}
	if (!event.locals.user.registered2FA) {
		return redirect(302, "/");
	}
	if (event.locals.session.twoFactorVerified) {
		return redirect(302, "/");
	}
	if (!event.locals.user.registeredPasskey) {
		return redirect(302, get2FARedirect(event.locals.user));
	}
	const credentials = getUserPasskeyCredentials(event.locals.user.id);
	return {
		credentials,
		user: event.locals.user
	};
}
