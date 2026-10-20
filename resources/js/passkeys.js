export function initializePasskeysComponent() {
    window.Alpine.data('coolifyPasskeys', () => ({
        busy: false,
        error: '',
        name: '',
        supported: window.isSecureContext
            && typeof PublicKeyCredential !== 'undefined'
            && typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function'
            && typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function'
            && typeof PublicKeyCredential.prototype.toJSON === 'function',

        async request(url, method = 'GET', body) {
            const response = await fetch(url, {
                method,
                credentials: 'same-origin',
                headers: {
                    Accept: 'application/json',
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content,
                },
                body: body === undefined ? undefined : JSON.stringify(body),
            });
            if (response.status === 423 || response.status === 401 || response.status === 419) {
                window.location.reload();
                throw new Error('Your session needs confirmation. Please try again after signing in.');
            }
            if (response.redirected && !response.headers.get('content-type')?.includes('application/json')) {
                window.location.assign(response.url);
                throw new Error('Please complete the account confirmation and try again.');
            }
            const result = response.status === 204 ? {} : await response.json();
            if (!response.ok) {
                throw new Error(Object.values(result.errors ?? {}).flat()[0] ?? result.message ?? 'The passkey request failed.');
            }
            return result;
        },

        async run(action) {
            if (this.busy) return;
            this.busy = true;
            this.error = '';
            try {
                await action();
            } catch (error) {
                this.error = error.name === 'NotAllowedError'
                    ? 'Passkey request cancelled or timed out. You can try again.'
                    : error.message;
            } finally {
                this.busy = false;
            }
        },

        login() {
            return this.run(async () => {
                const { options } = await this.request('/passkeys/login/options');
                const credential = await navigator.credentials.get({
                    publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
                });
                const result = await this.request('/passkeys/login', 'POST', { credential: credential.toJSON() });
                window.location.assign(result.redirect ?? '/');
            });
        },

        register() {
            return this.run(async () => {
                const { options } = await this.request('/user/passkeys/options');
                const credential = await navigator.credentials.create({
                    publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
                });
                await this.request('/user/passkeys', 'POST', { name: this.name, credential: credential.toJSON() });
                window.location.reload();
            });
        },

        remove(id) {
            return this.run(async () => {
                await this.request(`/user/passkeys/${encodeURIComponent(id)}`, 'DELETE');
                window.location.reload();
            });
        },
    }));
}
