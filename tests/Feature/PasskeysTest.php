<?php

use App\Actions\Server\UpdateCoolify;
use App\Livewire\Profile\Passkeys;
use App\Models\InstanceSettings;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Livewire\Livewire;

uses(RefreshDatabase::class);

function passkeyUser(): User
{
    $user = User::factory()->create();
    $user->teams()->update(['show_boarding' => false]);
    Cache::flush();

    return $user;
}

beforeEach(function () {
    config(['app.maintenance.store' => 'array', 'passkeys.relying_party_id' => 'coolify.example.com',
        'passkeys.allowed_origins' => ['https://coolify.example.com']]);
    InstanceSettings::forceCreate(['id' => 0, 'is_registration_enabled' => false]);
});

it('requires a signed in user to manage passkeys', function () {
    $this->getJson('/user/passkeys/options')->assertUnauthorized();
});

it('requires recent password confirmation before passkey enrollment', function () {
    $user = passkeyUser();

    $this->actingAs($user)->getJson('/user/passkeys/options')->assertStatus(423);
});

it('uses the configured hostname and requires device user verification', function () {
    $this->getJson('/passkeys/login/options')
        ->assertJsonPath('options.rpId', 'coolify.example.com')
        ->assertJsonPath('options.userVerification', 'required')
        ->assertSessionHas('passkey.verification_options');
});

it('allows confirmed users to request enrollment options for their own account', function () {
    $user = passkeyUser();

    $this->actingAs($user)->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->getJson('/user/passkeys/options')
        ->assertJsonPath('options.rp.id', 'coolify.example.com')
        ->assertJsonPath('options.user.name', $user->email)
        ->assertSessionHas('passkey.registration_options');
});

it('preserves the two factor challenge for password sign in', function () {
    $user = passkeyUser();
    $user->forceFill(['two_factor_secret' => encrypt('JBSWY3DPEHPK3PXP'), 'two_factor_confirmed_at' => now()])->save();

    $this->post('/login', ['email' => $user->email, 'password' => 'password'])
        ->assertRedirect('/two-factor-challenge');

    $this->assertGuest();
});

it('blocks upstream updates when the fork updater manages the instance', function () {
    config(['constants.coolify.fork_managed_updates' => true]);

    expect(fn () => app(UpdateCoolify::class)->handle(true))
        ->toThrow(RuntimeException::class, 'This instance deploys tested images from its GitHub fork.');
});

it('throttles passkey challenges', function () {
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $this->getJson('/passkeys/login/options')->assertOk();
    }

    $this->getJson('/passkeys/login/options')->assertTooManyRequests();
});

it('rejects malformed credentials without authenticating a user', function () {
    $this->postJson('/passkeys/login', ['credential' => ['id' => 'invalid']])->assertUnprocessable();

    $this->assertGuest();
});

it('shows only the current users passkeys and escapes their names', function () {
    $user = passkeyUser();
    $other = passkeyUser();
    $user->passkeys()->create(['name' => '<script>alert(1)</script>', 'credential_id' => 'own', 'credential' => []]);
    $other->passkeys()->create(['name' => 'Private other device', 'credential_id' => 'other', 'credential' => []]);

    Livewire::actingAs($user)->test(Passkeys::class)
        ->assertSee('<script>alert(1)</script>')
        ->assertDontSeeHtml('<script>alert(1)</script>')
        ->assertDontSee('Private other device');
});

it('prevents deleting another users passkey', function () {
    $user = passkeyUser();
    $other = passkeyUser();
    $passkey = $other->passkeys()->create(['name' => 'Other device', 'credential_id' => 'other', 'credential' => []]);

    $this->actingAs($user)->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->deleteJson('/user/passkeys/'.$passkey->id)->assertForbidden();

    $this->assertModelExists($passkey);
});

it('deletes an owned passkey after recent confirmation', function () {
    $user = passkeyUser();
    $passkey = $user->passkeys()->create(['name' => 'My device', 'credential_id' => 'own', 'credential' => []]);

    $this->actingAs($user)->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->deleteJson('/user/passkeys/'.$passkey->id)->assertSuccessful();

    $this->assertModelMissing($passkey);
});
