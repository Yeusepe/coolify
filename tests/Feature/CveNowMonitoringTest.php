<?php

use App\Jobs\ServerVulnerabilityCheckJob;
use App\Livewire\Server\Security\Vulnerabilities;
use App\Models\InstanceSettings;
use App\Models\Server;
use App\Models\Team;
use App\Models\User;
use App\Notifications\Server\VulnerabilitiesFound;
use App\Services\CveNowService;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Livewire\Livewire;

uses(RefreshDatabase::class);

function cveMonitoringServer(string $role = 'owner'): Server
{
    Server::flushIdentityMap();
    InstanceSettings::forceCreate(['id' => 0]);
    $team = Team::factory()->create();
    $user = User::factory()->create();
    $team->members()->attach($user->id, ['role' => $role]);
    test()->actingAs($user);
    session(['currentTeam' => $team]);
    $server = Server::factory()->create(['team_id' => $team->id]);
    $server->settings->update(['is_reachable' => true, 'is_usable' => true, 'force_disabled' => false]);
    config(['services.cve_now.enabled' => true]);

    return $server;
}

it('escapes advisory text and queues only one pending check', function () {
    Storage::fake('local');
    $server = cveMonitoringServer();
    Queue::fake([ServerVulnerabilityCheckJob::class]);
    app(CveNowService::class)->saveReport($server, ['checked_at' => now()->toIso8601String(), 'packages_checked' => 1, 'containers' => [], 'runtimes' => [], 'findings' => [['id' => 'CVE-2026-12345', 'title' => '<script>alert(1)</script>', 'score' => 9.1, 'package' => 'example', 'version' => '1.0.0', 'ecosystem' => 'npm', 'contexts' => ['api'], 'kind' => 'Package version match', 'fixed' => ['1.0.1'], 'url' => 'https://cve.now/CVE-2026-12345']]]);

    Livewire::test(Vulnerabilities::class, ['server_uuid' => $server->uuid])
        ->assertSee('&lt;script&gt;alert(1)&lt;/script&gt;', escape: false)
        ->assertDontSee('<script>alert(1)</script>', escape: false)
        ->call('refreshReport')->call('refreshReport');

    Queue::assertPushed(ServerVulnerabilityCheckJob::class, 1);
});

it('forbids security report access by a team member', function () {
    Storage::fake('local');
    $server = cveMonitoringServer('member');

    Livewire::test(Vulnerabilities::class, ['server_uuid' => $server->uuid])->assertForbidden();
});

it('does not disclose another teams vulnerability report', function () {
    Storage::fake('local');
    cveMonitoringServer();
    $other = Server::factory()->create(['team_id' => Team::factory()->create()->id]);

    expect(fn () => Livewire::test(Vulnerabilities::class, ['server_uuid' => $other->uuid]))->toThrow(ModelNotFoundException::class);
});

it('rejects unversioned additional packages without saving or queuing them', function () {
    Storage::fake('local');
    $server = cveMonitoringServer();
    Queue::fake([ServerVulnerabilityCheckJob::class]);

    Livewire::test(Vulnerabilities::class, ['server_uuid' => $server->uuid])->set('additionalPackages', 'npm:example@https://internal')->call('savePackages')->assertHasErrors('additionalPackages');

    expect(app(CveNowService::class)->settings($server))->toBe([]);
    Queue::assertNotPushed(ServerVulnerabilityCheckJob::class);
});

it('does not notify again for unchanged high severity matches', function () {
    Storage::fake('local');
    $server = cveMonitoringServer();
    Notification::fake();
    $server->team->discordNotificationSettings()->updateOrCreate([], ['discord_enabled' => true, 'discord_webhook_url' => 'https://discord.com/api/webhooks/test/test', 'server_patch_discord_notifications' => true]);
    expect($server->isFunctional())->toBeTrue();
    Http::preventStrayRequests();
    Http::fake(['cve.now/stack*' => Http::response(['packages' => 1, 'entries' => [['id' => 'CVE-2026-12345', 'title' => 'Example issue', 'severity' => ['cvss' => 9.1], 'matched' => ['ecosystem' => 'npm', 'name' => 'example', 'version' => '1.0.0'], 'affected' => []]]])]);
    $service = $this->partialMock(CveNowService::class, fn ($mock) => $mock->shouldReceive('collect')->andReturn(['packages' => [['ecosystem' => 'npm', 'name' => 'example', 'version' => '1.0.0', 'container' => 'api']], 'runtimes' => [], 'containers' => [], 'warnings' => []]));

    (new ServerVulnerabilityCheckJob($server))->handle($service);
    expect($service->report($server)['error'])->toBeNull();
    (new ServerVulnerabilityCheckJob($server))->handle($service);

    Notification::assertSentTo($server->team, VulnerabilitiesFound::class);
    Notification::assertSentTimes(VulnerabilitiesFound::class, 1);
    expect(Cache::has('cve-now:pending:'.$server->uuid))->toBeFalse();
});
