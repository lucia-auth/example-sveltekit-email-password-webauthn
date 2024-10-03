<script lang="ts">
	import { enhance } from "$app/forms";
	import { encodeBase64 } from "@oslojs/encoding";

	import type { PageData, ActionData } from "./$types";

	export let data: PageData;
	export let form: ActionData;
</script>

<header>
	<a href="/">Home</a>
	<a href="/settings">Settings</a>
</header>
<main>
	<h1>Settings</h1>
	<section>
		<h2>Update email</h2>
		<p>Your email: {data.user.email}</p>
		<form method="post" use:enhance action="?/update_email">
			<label for="form-email.email">New email</label>
			<input type="email" id="form-email.email" name="email" required /><br />
			<button>Update</button>
			<p>{form?.email?.message ?? ""}</p>
		</form>
	</section>
	<section>
		<h2>Update password</h2>
		<form method="post" use:enhance action="?/update_password">
			<label for="form-password.password">Current password</label>
			<input type="password" id="form-email.password" name="password" autocomplete="current-password" required /><br />
			<label for="form-password.new-password">New password</label>
			<input
				type="password"
				id="form-password.new-password"
				name="new_password"
				autocomplete="new-password"
				required
			/><br />
			<button>Update</button>
			<p>{form?.password?.message ?? ""}</p>
		</form>
	</section>
	<section>
		<h2>Authenticator app</h2>
		{#if data.user.registeredTOTP}
			<a href="/2fa/totp/setup">Update TOTP</a>
			<form method="post" use:enhance action="?/disconnect_totp">
				<button>Disconnect</button>
			</form>
		{:else}
			<a href="/2fa/totp/setup">Set up TOTP</a>
		{/if}
	</section>
	<section>
		<h2>Passkeys</h2>
		<p>Passkeys are WebAuthn credentials that validate your identity using your device.</p>
		<ul>
			{#each data.passkeyCredentials as credential}
				<li>
					<p>{credential.name}</p>
					<form method="post" use:enhance action="?/delete_passkey">
						<input type="hidden" name="credential_id" value={encodeBase64(credential.id)} />
						<button> Delete </button>
					</form>
				</li>
			{/each}
		</ul>
		<a href="/2fa/passkey/register">Add</a>
	</section>
	<section>
		<h2>Security keys</h2>
		<p>Security keys are WebAuthn credentials that can only be used for two-factor authentication.</p>
		<ul>
			{#each data.securityKeyCredentials as credential}
				<li>
					<p>{credential.name}</p>
					<form method="post" use:enhance action="?/delete_security_key">
						<input type="hidden" name="credential_id" value={encodeBase64(credential.id)} />
						<button>Delete</button>
					</form>
				</li>
			{/each}
		</ul>
		<a href="/2fa/security-key/register">Add</a>
	</section>
	{#if data.recoveryCode !== null}
		<section>
			<h1>Recovery code</h1>
			<p>Your recovery code is: {data.recoveryCode}}</p>
			<form method="post" use:enhance action="?/regenerate_recovery_code">
				<button>Generate new code</button>
			</form>
		</section>
	{/if}
</main>
