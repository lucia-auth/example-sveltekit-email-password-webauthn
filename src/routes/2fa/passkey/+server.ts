import {
	parseClientDataJSON,
	coseAlgorithmES256,
	ClientDataType,
	coseAlgorithmRS256,
	createAssertionSignatureMessage,
	parseAuthenticatorData
} from "@oslojs/webauthn";
import { decodePKIXECDSASignature, decodeSEC1PublicKey, p256, verifyECDSASignature } from "@oslojs/crypto/ecdsa";
import { ObjectParser } from "@pilcrowjs/object-parser";
import { decodeBase64 } from "@oslojs/encoding";
import { verifyWebAuthnChallenge, getUserPasskeyCredential } from "$lib/server/webauthn";
import { setSessionAs2FAVerified } from "$lib/server/session";
import { decodePKCS1RSAPublicKey, sha256ObjectIdentifier, verifyRSASSAPKCS1v15Signature } from "@oslojs/crypto/rsa";
import { sha256 } from "@oslojs/crypto/sha2";

import type { AuthenticatorData, ClientData } from "@oslojs/webauthn";
import type { RequestEvent } from "./$types";

export async function POST(event: RequestEvent) {
	if (event.locals.session === null || event.locals.user === null) {
		return new Response("Not authenticated", {
			status: 401
		});
	}
	if (
		!event.locals.user.emailVerified ||
		!event.locals.user.registeredPasskey ||
		event.locals.session.twoFactorVerified
	) {
		return new Response("Forbidden", {
			status: 403
		});
	}

	const data: unknown = await event.request.json();
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
	if (!authenticatorData.userPresent) {
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

	const credential = getUserPasskeyCredential(event.locals.user.id, credentialId);
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

	setSessionAs2FAVerified(event.locals.session.id);
	return new Response(null, {
		status: 204
	});
}
