import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Passkeys } from '@laravel/passkeys';

const events = [];
globalThis.window = { dispatchEvent: event => events.push(event.type) };
await import('../../resources/js/passkeys.js');

test('the passkey entrypoint exposes the native Laravel client and signals readiness', () => {
    assert.equal(window.Passkeys, Passkeys);
    assert.deepEqual(events, ['passkeys:ready']);
});

for (const [agent, expected] of [
    ['Mozilla/5.0 (Windows NT 10.0) Chrome/145.0 Safari/537.36 Edg/145.0', 'Edge on Windows'],
    ['Mozilla/5.0 (iPhone) AppleWebKit/605.1 Version/26.0 Mobile Safari/604.1', 'Safari on iOS'],
    ['Mozilla/5.0 (Linux; Android 16) Chrome/145.0 Mobile Safari/537.36', 'Chrome on Android'],
    ['Mozilla/5.0 (X11; Linux x86_64) Firefox/145.0', 'Firefox on Linux'],
    ['Unknown browser', 'Browser on device'],
]) {
    test(`the suggested passkey name is ${expected}`, () => {
        Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { userAgent: agent } });
        assert.equal(window.passkeyDeviceName(), expected);
    });
}
