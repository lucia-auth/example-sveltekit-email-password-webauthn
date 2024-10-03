import {
	parseClientDataJSON,
	coseAlgorithmES256,
	ClientDataType,
	parseAuthenticatorData,
	createAssertionSignatureMessage,
	coseAlgorithmRS256
} from "@oslojs/webauthn";
import { decodePKIXECDSASignature, decodeSEC1PublicKey, p256, verifyECDSASignature } from "@oslojs/crypto/ecdsa";
import { ObjectParser } from "@pilcrowjs/object-parser";
import { decodeBase64 } from "@oslojs/encoding";
import { verifyWebAuthnChallenge, getPasskeyCredential } from "$lib/server/webauthn";
import { createSession, generateSessionToken, setSessionTokenCookie } from "$lib/server/session";
import { sha256 } from "@oslojs/crypto/sha2";
import { decodePKCS1RSAPublicKey, sha256ObjectIdentifier, verifyRSASSAPKCS1v15Signature } from "@oslojs/crypto/rsa";

import type { RequestEvent } from "./$types";
import type { ClientData, AuthenticatorData } from "@oslojs/webauthn";
import type { SessionFlags } from "$lib/server/session";

// Stricter rate limiting can be omitted here since creating challenges are rate-limited
export async function POST(context: RequestEvent): Promise<Response> {
	const data: unknown = await context.request.json();
	const parser = new ObjectParser(data);
	let encodedAuthenticatorData: string;
	let encodedClientDataJSON: string;
	let encodedCredentialId: string;
	let encodedSignature: string;
	try {
		encodedAuthenticatorData = parser.getString("authenticator_data");
		encodedClientDataJSON = parser.getString("client_data_json");
		encodedCredentialId = parser.getString("credential_id");
		encodedSignature = parser.getString("signature");
	} catch {
		return new Response("Invalid or missing fields", {
			status: 400
		});
	}
	let authenticatorDataBytes: Uint8Array;
	let clientDataJSON: Uint8Array;
	let credentialId: Uint8Array;
	let signatureBytes: Uint8Array;
	try {
		authenticatorDataBytes = decodeBase64(encodedAuthenticatorData);
		clientDataJSON = decodeBase64(encodedClientDataJSON);
		credentialId = decodeBase64(encodedCredentialId);
		signatureBytes = decodeBase64(encodedSignature);
	} catch {
		return new Response("Invalid or missing fields", {
			status: 400
		});
	}

	let authenticatorData: AuthenticatorData;
	try {
		authenticatorData = parseAuthenticatorData(authenticatorDataBytes);
	} catch {
		return new Response("Invalid data", {
			status: 400
		});
	}
	// TODO: Update host
	if (!authenticatorData.verifyRelyingPartyIdHash("localhost")) {
		return new Response("Invalid data", {
			status: 400
		});
	}
	if (!authenticatorData.userPresent || !authenticatorData.userVerified) {
		return new Response("Invalid data", {
			status: 400
		});
	}

	let clientData: ClientData;
	try {
		clientData = parseClientDataJSON(clientDataJSON);
	} catch {
		return new Response("Invalid data", {
			status: 400
		});
	}
	if (clientData.type !== ClientDataType.Get) {
		return new Response("Invalid data", {
			status: 400
		});
	}

	if (!verifyWebAuthnChallenge(clientData.challenge)) {
		return new Response("Invalid data", {
			status: 400
		});
	}
	// TODO: Update origin
	if (clientData.origin !== "http://localhost:5173") {
		return new Response("Invalid data", {
			status: 400
		});
	}
	if (clientData.crossOrigin !== null && clientData.crossOrigin) {
		return new Response("Invalid data", {
			status: 400
		});
	}

	const credential = getPasskeyCredential(credentialId);
	if (credential === null) {
		return new Response("Invalid credential", {
			status: 400
		});
	}

	let validSignature: boolean;
	if (credential.algorithmId === coseAlgorithmES256) {
		const ecdsaSignature = decodePKIXECDSASignature(signatureBytes);
		const ecdsaPublicKey = decodeSEC1PublicKey(p256, credential.publicKey);
		const hash = sha256(createAssertionSignatureMessage(authenticatorDataBytes, clientDataJSON));
		validSignature = verifyECDSASignature(ecdsaPublicKey, hash, ecdsaSignature);
	} else if (credential.algorithmId === coseAlgorithmRS256) {
		const rsaPublicKey = decodePKCS1RSAPublicKey(credential.publicKey);
		const hash = sha256(createAssertionSignatureMessage(authenticatorDataBytes, clientDataJSON));
		validSignature = verifyRSASSAPKCS1v15Signature(rsaPublicKey, sha256ObjectIdentifier, hash, signatureBytes);
	} else {
		return new Response("Internal error", {
			status: 500
		});
	}

	if (!validSignature) {
		return new Response("Invalid signature", {
			status: 400
		});
	}
	const sessionFlags: SessionFlags = {
		twoFactorVerified: true
	};
	const sessionToken = generateSessionToken();
	const session = createSession(sessionToken, credential.userId, sessionFlags);
	setSessionTokenCookie(context, sessionToken, session.expiresAt);
	return new Response(null, {
		status: 204
	});
}
