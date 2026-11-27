<script lang="ts">
	import { api, ApiError, type User } from '#lib';

	let user = $state<User | null>(null);
	let loading = $state(true);
	let login = $state('');
	let password = $state('');
	let error = $state('');

	$effect(() => {
		api
			.me()
			.then((u) => (user = u))
			.catch(() => (user = null))
			.finally(() => (loading = false));
	});

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		try {
			user = await api.login(login, password);
			password = '';
		} catch (err) {
			error = err instanceof ApiError ? err.message : 'Could not reach the server';
		}
	}

	async function logout() {
		await api.logout();
		user = null;
	}
</script>

<svelte:head>
	<title>KumoKeep</title>
</svelte:head>

<main>
	<h1>KumoKeep</h1>

	{#if loading}
		<p>Loading…</p>
	{:else if user}
		<p>Signed in as <strong>{user.username}</strong> ({user.role}).</p>
		<button onclick={logout}>Sign out</button>
	{:else}
		<form onsubmit={submit}>
			<label>
				Username or email
				<input bind:value={login} autocomplete="username" required />
			</label>
			<label>
				Password
				<input type="password" bind:value={password} autocomplete="current-password" required />
			</label>
			{#if error}<p class="error" role="alert">{error}</p>{/if}
			<button type="submit">Sign in</button>
		</form>
	{/if}
</main>

<style>
	main {
		max-width: 22rem;
		margin: 4rem auto;
		font-family: system-ui, sans-serif;
	}
	form {
		display: grid;
		gap: 0.75rem;
	}
	label {
		display: grid;
		gap: 0.25rem;
	}
	.error {
		color: #b00020;
	}
</style>
