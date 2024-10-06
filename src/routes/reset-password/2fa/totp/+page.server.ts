import { verifyTOTP } from "@oslojs/otp";
import { validatePasswordResetSessionRequest, setPasswordResetSessionAs2FAVerified } from "$lib/server/password-reset";
import { totpBucket, getUserTOTPKey } from "$lib/server/totp";
import { fail, redirect } from "@sveltejs/kit";
import { getPasswordReset2FARedirect } from "$lib/server/2fa";

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
	if (!user.registeredTOTP) {
		return redirect(302, getPasswordReset2FARedirect(user));
	}
	return {
		user
	};
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
	if (!session.emailVerified || !user.registeredTOTP || session.twoFactorVerified) {
		return fail(403, {
			message: "Forbidden"
		});
	}
	if (!totpBucket.check(session.userId, 1)) {
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
	const totpKey = getUserTOTPKey(session.userId);
	if (totpKey === null) {
		return fail(403, {
			message: "Forbidden"
		});
	}
	if (!totpBucket.consume(session.userId, 1)) {
		return fail(429, {
			message: "Too many requests"
		});
	}
	if (!verifyTOTP(totpKey, 30, 6, code)) {
		return fail(400, {
			message: "Invalid code"
		});
	}
	totpBucket.reset(session.userId);
	setPasswordResetSessionAs2FAVerified(session.id);
	return redirect(302, "/reset-password");
}
