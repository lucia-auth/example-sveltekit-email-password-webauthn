<script lang="ts">
	import { encodeBase64 } from "@oslojs/encoding";
	import { createChallenge } from "$lib/client/webauthn";
	import { enhance } from "$app/forms";

	import type { ActionData, PageData } from "./$types";

	export let data: PageData;
	export let form: ActionData;

	let encodedAttestationObject: string | null = null;
	let encodedClientDataJSON: string | null = null;
</script>

<h1>Register security key</h1>
<button
	disabled={encodedAttestationObject !== null && encodedClientDataJSON !== null}
	on:click={async () => {
		const challenge = await createChallenge();

		const credential = await navigator.credentials.create({
			publicKey: {
				challenge,
				user: {
					displayName: data.user.username,
					id: data.credentialUserId,
					name: data.user.email
				},
				rp: {
					name: "SvelteKit WebAuthn example"
				},
				pubKeyCredParams: [
					{
						alg: -7,
						type: "public-key"
					},
					{
						alg: -257,
						type: "public-key"
					}
				],
				attestation: "none",
				authenticatorSelection: {
					userVerification: "discouraged",
					residentKey: "discouraged",
					requireResidentKey: false,
					authenticatorAttachment: "cross-platform"
				},
				excludeCredentials: data.credentials.map((credential) => {
					return {
						id: credential.id,
						type: "public-key"
					};
				})
			}
		});

		if (!(credential instanceof PublicKeyCredential)) {
			throw new Error("Failed to create public key");
		}
		if (!(credential.response instanceof AuthenticatorAttestationResponse)) {
			throw new Error("Unexpected error");
		}

		encodedAttestationObject = encodeBase64(new Uint8Array(credential.response.attestationObject));
		encodedClientDataJSON = encodeBase64(new Uint8Array(credential.response.clientDataJSON));
	}}>Create credential</button
>
<form method="post" use:enhance>
	<label for="form-register-credential.name">Credential name</label>
	<input id="form-register-credential.name" name="name" />
	<input type="hidden" name="attestation_object" value={encodedAttestationObject} />
	<input type="hidden" name="client_data_json" value={encodedClientDataJSON} />
	<button disabled={encodedAttestationObject === null && encodedClientDataJSON === null}>Continue</button>
	<p>{form?.message ?? ""}</p>
</form>
