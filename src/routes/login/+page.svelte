<script lang="ts">
	import { enhance } from "$app/forms";
	import { createChallenge } from "$lib/client/webauthn";
	import { encodeBase64 } from "@oslojs/encoding";
	import { goto } from "$app/navigation";

	import type { ActionData } from "./$types";

	export let form: ActionData;

	let passkeyErrorMessage = "";
</script>

<h1>Sign in</h1>
<form method="post" use:enhance>
	<label for="form-login.email">Email</label>
	<input
		type="email"
		id="form-login.email"
		name="email"
		autocomplete="username"
		required
		value={form?.email ?? ""}
	/><br />
	<label for="form-login.password">Password</label>
	<input type="password" id="form-login.password" name="password" autocomplete="current-password" required /><br />
	<button>Continue</button>
	<p>{form?.message ?? ""}</p>
</form>
<div>
	<button
		on:click={async () => {
			const challenge = await createChallenge();

			const credential = await navigator.credentials.get({
				publicKey: {
					challenge,
					userVerification: "required"
				}
			});

			if (!(credential instanceof PublicKeyCredential)) {
				throw new Error("Failed to create public key");
			}
			if (!(credential.response instanceof AuthenticatorAssertionResponse)) {
				throw new Error("Unexpected error");
			}

			const response = await fetch("/login/passkey", {
				method: "POST",
				// this example uses JSON but you can use something like CBOR to get something more compact
				body: JSON.stringify({
					credential_id: encodeBase64(new Uint8Array(credential.rawId)),
					signature: encodeBase64(new Uint8Array(credential.response.signature)),
					authenticator_data: encodeBase64(new Uint8Array(credential.response.authenticatorData)),
					client_data_json: encodeBase64(new Uint8Array(credential.response.clientDataJSON))
				})
			});

			if (response.ok) {
				goto("/");
			} else {
				passkeyErrorMessage = await response.text();
			}
		}}>Sign in with passkeys</button
	>
	<p>{passkeyErrorMessage}</p>
</div>
<a href="/signup">Create an account</a>
<a href="/forgot-password">Forgot password?</a>
