<?php

use App\Jobs\ServerVulnerabilityCheckJob;
use App\Livewire\Server\Security\Vulnerabilities;
use App\Models\Application;
use App\Models\Environment;
use App\Models\InstanceSettings;
use App\Models\Project;
use App\Models\Server;
use App\Models\Service;
use App\Models\StandaloneDocker;
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

it('keeps uncertain runtime advisories visible without urgent notifications', function () {
    Storage::fake('local');
    $server = cveMonitoringServer();
    Notification::fake();
    $server->team->discordNotificationSettings()->updateOrCreate([], ['discord_enabled' => true, 'discord_webhook_url' => 'https://discord.com/api/webhooks/test/test', 'server_patch_discord_notifications' => true]);
    Http::preventStrayRequests();
    Http::fake([
        'cve.now/feed*' => Http::response(['items' => [['id' => 'CVE-2026-12345']]]),
        'cve.now/api/v1/entries/CVE-2026-12345' => Http::response(['id' => 'CVE-2026-12345', 'title' => 'Review needed', 'severity' => ['cvss' => 9.8], 'affected' => [['product' => 'PHP', 'ranges' => []]]]),
        'www.php.net/releases/*' => Http::response(['version' => '8.4.27']),
    ]);
    $service = $this->partialMock(CveNowService::class, fn ($mock) => $mock->shouldReceive('collect')->andReturn(['packages' => [], 'runtimes' => [['name' => 'php', 'version' => '8.4.27', 'container' => 'control']], 'containers' => [], 'warnings' => []]));

    (new ServerVulnerabilityCheckJob($server))->handle($service);

    expect($service->report($server)['findings'])->toHaveCount(1)
        ->and($service->report($server)['notified'])->toBe([]);
    Notification::assertNothingSent();
});

it('maps container versions to owned applications and service names without disclosing another team', function () {
    $server = cveMonitoringServer();
    $project = Project::factory()->create(['team_id' => $server->team_id]);
    $environment = Environment::factory()->create(['project_id' => $project->id]);
    $destination = $server->standaloneDockers()->firstOrFail();
    $application = Application::factory()->create(['name' => 'Creator Payments', 'environment_id' => $environment->id, 'destination_id' => $destination->id, 'destination_type' => StandaloneDocker::class]);
    $service = Service::factory()->create(['name' => 'Payments infrastructure', 'environment_id' => $environment->id, 'server_id' => $server->id]);
    $otherProject = Project::factory()->create(['team_id' => Team::factory()->create()->id]);
    $otherEnvironment = Environment::factory()->create(['project_id' => $otherProject->id]);
    $other = Application::factory()->create(['name' => 'Other team private app', 'environment_id' => $otherEnvironment->id, 'destination_id' => $destination->id, 'destination_type' => StandaloneDocker::class]);
    $inventory = ['packages' => [['name' => 'next', 'version' => '16.4.2', 'ecosystem' => 'npm', 'container' => $application->uuid.'-20261025']], 'runtimes' => [['name' => 'redis', 'version' => '7.4.8', 'container' => 'redis-'.$service->uuid]], 'containers' => [['name' => $other->uuid, 'image' => 'private-image']]];

    $identified = app(CveNowService::class)->identifyResources($server, $inventory);

    expect($identified['packages'][0]['container'])->toBe('Creator Payments');
    expect($identified['runtimes'][0]['container'])->toBe('Payments infrastructure / redis');
    expect($identified['containers'][0]['resource'])->toBe($other->uuid);
});
