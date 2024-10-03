import { db } from "./db";
import { generateRandomRecoveryCode } from "./utils";
import { ExpiringTokenBucket } from "./rate-limit";
import { decryptToString, encryptString } from "./encryption";

import type { User } from "./user";

export const recoveryCodeBucket = new ExpiringTokenBucket<number>(3, 60 * 60);

export function resetUser2FAWithRecoveryCode(userId: number, recoveryCode: string): boolean {
	// Note: In Postgres and MySQL, these queries should be done in a transaction using SELECT FOR UPDATE
	const row = db.queryOne("SELECT recovery_code FROM user WHERE id = ?", [userId]);
	if (row === null) {
		return false;
	}
	const encryptedRecoveryCode = row.bytes(0);
	const userRecoveryCode = decryptToString(encryptedRecoveryCode);
	if (recoveryCode !== userRecoveryCode) {
		return false;
	}

	const newRecoveryCode = generateRandomRecoveryCode();
	const encryptedNewRecoveryCode = encryptString(newRecoveryCode);

	try {
		db.execute("BEGIN TRANSACTION", []);
		// Compare old recovery code to ensure recovery code wasn't updated.
		const result = db.execute("UPDATE user SET recovery_code = ? WHERE id = ? AND recovery_code = ?", [
			encryptedNewRecoveryCode,
			userId,
			encryptedRecoveryCode
		]);
		if (result.changes < 1) {
			db.execute("ROLLBACK", []);
			return false;
		}
		db.execute("UPDATE session SET two_factor_verified = 0 WHERE user_id = ?", [userId]);
		db.execute("DELETE FROM totp_credential WHERE user_id = ?", [userId]);
		db.execute("DELETE FROM passkey_credential WHERE user_id = ?", [userId]);
		db.execute("DELETE FROM security_key_credential WHERE user_id = ?", [userId]);
		db.execute("COMMIT", []);
	} catch (e) {
		if (db.inTransaction()) {
			db.execute("ROLLBACK", []);
		}
		throw e;
	}
	return true;
}

export function get2FARedirect(user: User): string {
	if (user.registeredPasskey) {
		return "/2fa/passkey";
	}
	if (user.registeredSecurityKey) {
		return "/2fa/security-key";
	}
	if (user.registeredTOTP) {
		return "/2fa/totp";
	}
	return "/2fa/setup";
}

export function getPasswordReset2FARedirect(user: User): string {
	if (user.registeredPasskey) {
		return "/reset-password/2fa/passkey";
	}
	if (user.registeredSecurityKey) {
		return "/reset-password/2fa/security-key";
	}
	if (user.registeredTOTP) {
		return "/reset-password/2fa/totp";
	}
	return "/2fa/setup";
}
