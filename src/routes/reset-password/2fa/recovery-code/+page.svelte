<script lang="ts">
	import { enhance } from "$app/forms";

	import type { ActionData, PageData } from "./$types";

	export let data: PageData;
	export let form: ActionData;
</script>

<h1>Use your recovery code</h1>
<form method="post" use:enhance>
	<label for="form-recovery-code.code">Recovery code</label>
	<input id="form-recovery-code.code" name="code" required /><br />
	<button>Verify</button>
	<p>{form?.message ?? ""}</p>
</form>
{#if data.user.registeredSecurityKey}
	<a href="/reset-password/2fa/security-key">Use security keys</a>
{/if}
{#if data.user.registeredPasskey}
	<a href="/reset-password/2fa/passkey">Use passkeys</a>
{/if}
{#if data.user.registeredTOTP}
	<a href="/reset-password/2fa/totp">Use authenticator apps</a>
{/if}
