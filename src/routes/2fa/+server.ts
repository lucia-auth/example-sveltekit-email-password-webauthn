import { get2FARedirect } from "$lib/server/2fa";
import { redirect } from "@sveltejs/kit";

import type { RequestEvent } from "./$types";

export function GET(event: RequestEvent): Response {
	if (event.locals.session === null || event.locals.user === null) {
		return redirect(302, "/login");
	}
	if (event.locals.session.twoFactorVerified) {
		return redirect(302, "/");
	}
	if (!event.locals.user.registered2FA) {
		return redirect(302, "/2fa/setup");
	}
	return redirect(302, get2FARedirect(event.locals.user));
}
