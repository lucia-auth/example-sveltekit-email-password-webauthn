import { validatePasswordResetSessionRequest } from "$lib/server/password-reset";
import { fail, redirect } from "@sveltejs/kit";
import { recoveryCodeBucket, resetUser2FAWithRecoveryCode } from "$lib/server/2fa";

import type { Actions, RequestEvent } from "./$types";

export async function load(event: RequestEvent) {
	const { session, user } = validatePasswordResetSessionRequest(event);

	if (session === null) {
		return redirect(302, "/forgot-password");
	}
	if (!session.emailVerified) {
		return redirect(302, "/reset-password/verify-email");
	}
	if (!user.registered2FA) {
		return redirect(302, "/reset-password");
	}
	if (session.twoFactorVerified) {
		return redirect(302, "/reset-password");
	}
	return {};
}

export const actions: Actions = {
	default: action
};

async function action(event: RequestEvent) {
	const { session, user } = validatePasswordResetSessionRequest(event);
	if (session === null) {
		return fail(401, {
			message: "Not authenticated"
		});
	}
	if (!session.emailVerified || !user.registered2FA || session.twoFactorVerified) {
		return fail(403, {
			message: "Forbidden"
		});
	}

	if (!recoveryCodeBucket.check(session.userId, 1)) {
		return fail(429, {
			message: "Too many requests"
		});
	}
	const formData = await event.request.formData();
	const code = formData.get("code");
	if (typeof code !== "string") {
		return fail(400, {
			message: "Invalid or missing fields"
		});
	}
	if (code === "") {
		return fail(400, {
			message: "Please enter your code"
		});
	}
	if (!recoveryCodeBucket.consume(session.userId, 1)) {
		return fail(429, {
			message: "Too many requests"
		});
	}
	const valid = resetUser2FAWithRecoveryCode(session.userId, code);
	if (!valid) {
		return fail(400, {
			message: "Invalid code"
		});
	}
	recoveryCodeBucket.reset(session.userId);
	return redirect(302, "/reset-password");
}
