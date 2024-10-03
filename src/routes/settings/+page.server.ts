import {
	createEmailVerificationRequest,
	sendVerificationEmail,
	sendVerificationEmailBucket,
	setEmailVerificationRequestCookie
} from "$lib/server/email-verification";
import { fail, redirect } from "@sveltejs/kit";
import { checkEmailAvailability, verifyEmailInput } from "$lib/server/email";
import { verifyPasswordHash, verifyPasswordStrength } from "$lib/server/password";
import { getUserPasswordHash, getUserRecoverCode, resetUserRecoveryCode, updateUserPassword } from "$lib/server/user";
import {
	createSession,
	generateSessionToken,
	invalidateUserSessions,
	setSessionTokenCookie
} from "$lib/server/session";
import {
	deleteUserPasskeyCredential,
	deleteUserSecurityKeyCredential,
	getUserPasskeyCredentials,
	getUserSecurityKeyCredentials
} from "$lib/server/webauthn";
import { decodeBase64 } from "@oslojs/encoding";
import { get2FARedirect } from "$lib/server/2fa";
import { deleteUserTOTPKey, totpUpdateBucket } from "$lib/server/totp";

import type { Actions, RequestEvent } from "./$types";
import type { SessionFlags } from "$lib/server/session";

export async function load(event: RequestEvent) {
	if (event.locals.user === null || event.locals.session === null) {
		return redirect(302, "/login");
	}
	if (event.locals.user.registered2FA && !event.locals.session.twoFactorVerified) {
		return redirect(302, get2FARedirect(event.locals.user));
	}
	let recoveryCode: string | null = null;
	if (event.locals.user.registered2FA) {
		recoveryCode = getUserRecoverCode(event.locals.user.id);
	}
	const passkeyCredentials = getUserPasskeyCredentials(event.locals.user.id);
	const securityKeyCredentials = getUserSecurityKeyCredentials(event.locals.user.id);
	return {
		recoveryCode,
		user: event.locals.user,
		passkeyCredentials,
		securityKeyCredentials
	};
}

export const actions: Actions = {
	update_password: updatePasswordAction,
	update_email: updateEmailAction,
	disconnect_totp: disconnectTOTPAction,
	delete_passkey: deletePasskeyAction,
	delete_security_key: deleteSecurityKeyAction,
	regenerate_recovery_code: regenerateRecoveryCodeAction
};

async function updatePasswordAction(event: RequestEvent) {
	if (event.locals.user === null || event.locals.session === null) {
		return fail(401, {
			password: {
				message: "Not authenticated"
			}
		});
	}
	if (!event.locals.user.emailVerified) {
		return fail(403, {
			password: {
				message: "Forbidden"
			}
		});
	}
	if (event.locals.user.registered2FA && !event.locals.session.twoFactorVerified) {
		return fail(403, {
			password: {
				message: "Forbidden"
			}
		});
	}
	const formData = await event.request.formData();
	const password = formData.get("password");
	const newPassword = formData.get("new_password");
	if (typeof password !== "string" || typeof newPassword !== "string") {
		return fail(400, {
			password: {
				message: "Invalid or missing fields"
			}
		});
	}
	const strongPassword = await verifyPasswordStrength(newPassword);
	if (!strongPassword) {
		return fail(400, {
			password: {
				message: "Weak password"
			}
		});
	}
	const passwordHash = getUserPasswordHash(event.locals.user.id);
	const validPassword = await verifyPasswordHash(passwordHash, password);
	if (!validPassword) {
		return fail(400, {
			password: {
				message: "Incorrect password"
			}
		});
	}
	invalidateUserSessions(event.locals.user.id);
	await updateUserPassword(event.locals.user.id, newPassword);

	const sessionToken = generateSessionToken();
	const sessionFlags: SessionFlags = {
		twoFactorVerified: event.locals.session.twoFactorVerified
	};
	const session = createSession(sessionToken, event.locals.user.id, sessionFlags);
	setSessionTokenCookie(event, sessionToken, session.expiresAt);
	return {
		password: {
			message: "Updated password"
		}
	};
}

async function updateEmailAction(event: RequestEvent) {
	if (event.locals.session === null || event.locals.user === null) {
		return fail(401, {
			email: {
				message: "Not authenticated"
			}
		});
	}
	if (event.locals.user.registered2FA && !event.locals.session.twoFactorVerified) {
		return fail(403, {
			email: {
				message: "Forbidden"
			}
		});
	}
	if (!sendVerificationEmailBucket.check(event.locals.user.id, 1)) {
		return fail(429, {
			email: {
				message: "Too many requests"
			}
		});
	}

	const formData = await event.request.formData();
	const email = formData.get("email");
	if (typeof email !== "string") {
		return fail(400, {
			email: {
				message: "Invalid or missing fields"
			}
		});
	}
	if (email === "") {
		return fail(400, {
			email: {
				message: "Please enter your email"
			}
		});
	}
	if (!verifyEmailInput(email)) {
		return fail(400, {
			email: {
				message: "Please enter a valid email"
			}
		});
	}
	const emailAvailable = checkEmailAvailability(email);
	if (!emailAvailable) {
		return fail(400, {
			email: {
				message: "This email is already used"
			}
		});
	}
	if (!sendVerificationEmailBucket.consume(event.locals.user.id, 1)) {
		return fail(429, {
			email: {
				message: "Too many requests"
			}
		});
	}
	const verificationRequest = createEmailVerificationRequest(event.locals.user.id, email);
	sendVerificationEmail(verificationRequest.email, verificationRequest.code);
	setEmailVerificationRequestCookie(event, verificationRequest);
	return redirect(302, "/verify-email");
}

async function disconnectTOTPAction(event: RequestEvent) {
	if (event.locals.session === null || event.locals.user === null) {
		return fail(401);
	}
	if (!event.locals.user.emailVerified) {
		return fail(403);
	}
	if (event.locals.user.registered2FA && !event.locals.session.twoFactorVerified) {
		return fail(403);
	}
	if (!totpUpdateBucket.consume(event.locals.user.id, 1)) {
		return fail(429);
	}
	deleteUserTOTPKey(event.locals.user.id);
	return {};
}

async function deletePasskeyAction(event: RequestEvent) {
	if (event.locals.user === null || event.locals.session === null) {
		return fail(401);
	}
	if (!event.locals.user.emailVerified) {
		return fail(403);
	}
	if (event.locals.user.registered2FA && !event.locals.session.twoFactorVerified) {
		return fail(403);
	}
	const formData = await event.request.formData();
	const encodedCredentialId = formData.get("credential_id");
	if (typeof encodedCredentialId !== "string") {
		return fail(400);
	}
	let credentialId: Uint8Array;
	try {
		credentialId = decodeBase64(encodedCredentialId);
	} catch {
		return fail(400);
	}
	const deleted = deleteUserPasskeyCredential(event.locals.user.id, credentialId);
	if (!deleted) {
		return fail(400);
	}
	return {};
}

async function deleteSecurityKeyAction(event: RequestEvent) {
	if (event.locals.user === null || event.locals.session === null) {
		return fail(401);
	}
	if (!event.locals.user.emailVerified) {
		return fail(403);
	}
	if (event.locals.user.registered2FA && !event.locals.session.twoFactorVerified) {
		return fail(403);
	}
	const formData = await event.request.formData();
	const encodedCredentialId = formData.get("credential_id");
	if (typeof encodedCredentialId !== "string") {
		return fail(400);
	}
	let credentialId: Uint8Array;
	try {
		credentialId = decodeBase64(encodedCredentialId);
	} catch {
		return fail(400);
	}
	const deleted = deleteUserSecurityKeyCredential(event.locals.user.id, credentialId);
	if (!deleted) {
		return fail(400);
	}
	return {};
}

async function regenerateRecoveryCodeAction(event: RequestEvent) {
	if (event.locals.session === null || event.locals.user === null) {
		return fail(401);
	}
	if (!event.locals.user.emailVerified) {
		return fail(403);
	}
	if (!event.locals.session.twoFactorVerified) {
		return fail(403);
	}
	resetUserRecoveryCode(event.locals.session.userId);
	return {};
}