import { db } from "./db";
import { decrypt, encrypt } from "./encryption";
import { ExpiringTokenBucket, RefillingTokenBucket } from "./rate-limit";

export const totpBucket = new ExpiringTokenBucket<number>(5, 60 * 30);
export const totpUpdateBucket = new RefillingTokenBucket<number>(3, 60 * 10);

export function getUserTOTPKey(userId: number): Uint8Array | null {
	const row = db.queryOne("SELECT totp_credential.key FROM totp_credential WHERE user_id = ?", [userId]);
	if (row === null) {
		throw new Error("Invalid user ID");
	}
	const encrypted = row.bytesNullable(0);
	if (encrypted === null) {
		return null;
	}
	return decrypt(encrypted);
}

export function updateUserTOTPKey(userId: number, key: Uint8Array): void {
	const encrypted = encrypt(key);
	try {
		db.execute("BEGIN TRANSACTION", []);
		db.execute("DELETE FROM totp_credential WHERE user_id = ?", [userId]);
		db.execute("INSERT INTO totp_credential (user_id, key) VALUES (?, ?)", [userId, encrypted]);
		db.execute("COMMIT", []);
	} catch (e) {
		if (db.inTransaction()) {
			db.execute("ROLLBACK", []);
		}
		throw e;
	}
}

export function deleteUserTOTPKey(userId: number): void {
	db.execute("DELETE FROM totp_credential WHERE user_id = ?", [userId]);
}
