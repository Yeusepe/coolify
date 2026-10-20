import assert from 'node:assert/strict';
import { test } from 'node:test';
import { initializePasskeysComponent } from '../../resources/js/passkeys.js';

function component() {
    let factory;
    const navigation = [];
    globalThis.window = {
        isSecureContext: true,
        Alpine: { data: (_name, value) => { factory = value; } },
        location: { assign: value => navigation.push(value), reload: () => navigation.push('reload') },
    };
    globalThis.document = { querySelector: () => ({ content: 'csrf-test' }) };
    globalThis.PublicKeyCredential = class {
        static parseCreationOptionsFromJSON(value) { return value; }
        static parseRequestOptionsFromJSON(value) { return value; }
        toJSON() { return { id: 'credential-test' }; }
    };
    initializePasskeysComponent();
    return { state: factory(), navigation };
}

test('login sends the browser assertion with CSRF protection and follows the server redirect', async () => {
    const { state, navigation } = component();
    const requests = [];
    globalThis.fetch = async (url, options) => {
        requests.push({ url, ...options });
        return new Response(JSON.stringify(requests.length === 1 ? { options: { challenge: 'test' } } : { redirect: '/' }));
    };
    Object.defineProperty(globalThis, 'navigator', { configurable: true, value: {
        credentials: { get: async ({ publicKey }) => {
            assert.equal(publicKey.challenge, 'test');
            return new PublicKeyCredential();
        } },
    } });

    await state.login();

    assert.equal(requests[1].url, '/passkeys/login');
    assert.equal(requests[1].headers['X-CSRF-TOKEN'], 'csrf-test');
    assert.equal(requests[1].credentials, 'same-origin');
    assert.deepEqual(JSON.parse(requests[1].body), { credential: { id: 'credential-test' } });
    assert.deepEqual(navigation, ['/']);
    assert.equal(state.busy, false);
});

test('registration sends the chosen name and new browser credential', async () => {
    const { state, navigation } = component();
    state.name = 'My device';
    const requests = [];
    globalThis.fetch = async (url, options) => {
        requests.push({ url, ...options });
        return new Response(JSON.stringify({ options: { challenge: 'test' } }));
    };
    Object.defineProperty(globalThis, 'navigator', { configurable: true, value: {
        credentials: { create: async () => new PublicKeyCredential() },
    } });

    await state.register();

    assert.equal(requests[1].url, '/user/passkeys');
    assert.deepEqual(JSON.parse(requests[1].body), { name: 'My device', credential: { id: 'credential-test' } });
    assert.deepEqual(navigation, ['reload']);
});

test('cancelled authentication leaves password login available and resets loading state', async () => {
    const { state, navigation } = component();
    globalThis.fetch = async () => new Response(JSON.stringify({ options: {} }));
    Object.defineProperty(globalThis, 'navigator', { configurable: true, value: {
        credentials: { get: async () => { throw new DOMException('Cancelled', 'NotAllowedError'); } },
    } });

    await state.login();

    assert.match(state.error, /cancelled or timed out/);
    assert.equal(state.busy, false);
    assert.deepEqual(navigation, []);
});

test('expired password confirmation reloads the protected page without creating a credential', async () => {
    const { state, navigation } = component();
    globalThis.fetch = async () => new Response('{}', { status: 423 });
    Object.defineProperty(globalThis, 'navigator', { configurable: true, value: {
        credentials: { create: async () => assert.fail('Must confirm the session first') },
    } });

    await state.register();

    assert.deepEqual(navigation, ['reload']);
    assert.match(state.error, /session needs confirmation/);
});
