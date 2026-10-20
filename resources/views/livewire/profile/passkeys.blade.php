<div x-data="coolifyPasskeys()" class="mt-8 flex flex-col gap-6 lg:mt-3">
    <x-slot:title>Passkeys | Coolify</x-slot>
    <div>
        <h1>Passkeys</h1>
        <p class="text-sm text-fg-dim">Use your fingerprint, face, device PIN, or security key to sign in. Your password and two-factor authentication remain available.</p>
        <a class="button mt-3" href="{{ route('profile') }}">Back to profile</a>
    </div>
    <section class="application-settings-section">
        <div class="application-settings-section-header"><h2>Add a passkey</h2></div>
        <form class="application-settings-section-body flex flex-col gap-3" x-on:submit.prevent="register()">
            <label for="passkey-name">Passkey name</label>
            <input id="passkey-name" class="input" type="text" x-model="name" maxlength="255" required placeholder="My password manager">
            <div><x-forms.button type="submit" isHighlighted x-bind:disabled="busy || !supported">Add passkey</x-forms.button></div>
            <p x-show="!supported" x-cloak class="text-sm text-fg-dim">Use HTTPS and a current browser to add passkeys.</p>
            <p x-show="error" x-text="error" x-cloak role="alert" class="text-sm text-red-500"></p>
        </form>
    </section>
    <section class="application-settings-section">
        <div class="application-settings-section-header"><h2>Your passkeys</h2></div>
        <div class="application-settings-section-body flex flex-col gap-3">
            @forelse ($passkeys as $passkey)
                <div class="flex items-center justify-between gap-4" wire:key="passkey-{{ $passkey->id }}">
                    <div>
                        <p>{{ $passkey->name }}</p>
                        <p class="text-xs text-fg-dim">Last used: {{ $passkey->last_used_at?->diffForHumans() ?? 'Never' }}</p>
                    </div>
                    <x-forms.button type="button" isError x-bind:disabled="busy"
                        x-on:click="remove(@js((string) $passkey->id))">Remove</x-forms.button>
                </div>
            @empty
                <p class="text-sm text-fg-dim">You have no passkeys yet. Add one above and keep another recovery method available.</p>
            @endforelse
        </div>
    </section>
</div>
