<script lang="ts">
	import { enhance } from "$app/forms";

	import type { ActionData } from "./$types";

	export let form: ActionData;
</script>

<h1>Use your recovery code</h1>
<form method="post" use:enhance>
	<label for="form-recovery-code.code">Recovery code</label>
	<input id="form-recovery-code.code" name="code" required /><br />
	<button>Verify</button>
	<p>{form?.message ?? ""}</p>
</form>