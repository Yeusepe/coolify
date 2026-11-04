<?php

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

it('adds the upstream passkey setting without recreating the forks credential table', function () {
    $user = User::factory()->create();
    $passkey = $user->passkeys()->create([
        'name' => 'Existing security key',
        'credential_id' => 'existing-fork-credential',
        'credential' => ['aaguid' => '00000000-0000-0000-0000-000000000000'],
    ]);
    $migration = require database_path('migrations/2026_10_12_164601_create_passkeys_table.php');

    $migration->down();

    expect(Schema::hasTable('passkeys'))->toBeTrue()
        ->and(Schema::hasColumn('instance_settings', 'is_passkey_enabled'))->toBeFalse();
    $this->assertModelExists($passkey);

    $migration->up();

    $this->assertModelExists($passkey);
    expect(Schema::hasColumn('instance_settings', 'is_passkey_enabled'))->toBeTrue();
});
