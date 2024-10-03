import { redirect } from "@sveltejs/kit";
import { getPasswordReset2FARedirect } from "$lib/server/2fa";
import { validatePasswordResetSessionRequest } from "$lib/server/password-reset";

import type { RequestEvent } from "./$types";

export async function GET(event: RequestEvent) {
	const { session, user } = validatePasswordResetSessionRequest(event);
	if (session === null) {
		return redirect(302, "/login");
	}
	if (!user.registered2FA || session.twoFactorVerified) {
		return redirect(302, "/reset-password");
	}
	return redirect(302, getPasswordReset2FARedirect(user));
}
