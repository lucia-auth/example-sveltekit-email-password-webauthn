import { getPasswordReset2FARedirect } from "$lib/server/2fa";
import { validatePasswordResetSessionRequest } from "$lib/server/password-reset";

import type { RequestEvent } from "./$types";

export async function GET(event: RequestEvent) {
	const { session, user } = validatePasswordResetSessionRequest(event);
	if (session === null) {
		return new Response(null, {
			status: 302,
			headers: {
				Location: "/login"
			}
		});
	}
	if (!user.registered2FA || session.twoFactorVerified) {
		return new Response(null, {
			status: 302,
			headers: {
				Location: "/reset-password"
			}
		});
	}
	return new Response(null, {
		status: 302,
		headers: {
			Location: getPasswordReset2FARedirect(user)
		}
	});
}
