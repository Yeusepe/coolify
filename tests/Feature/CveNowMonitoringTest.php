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
use App\Services\CweService;
use App\Services\SoftwareRecommendationService;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Sleep;
use Livewire\Livewire;

uses(RefreshDatabase::class);

it('shows escaped CWE labels for active and reviewed advisories', function () {
    Storage::fake('local');
    $server = cveMonitoringServer();
    $finding = ['id' => 'CVE-2026-12345', 'title' => 'Example advisory', 'score' => 5.0, 'package' => 'example', 'version' => '1.0.0', 'ecosystem' => 'npm', 'contexts' => ['API'], 'kind' => 'Package version match', 'fixed' => [], 'url' => 'https://cve.now/CVE-2026-12345', 'cwes' => [['id' => 'CWE-79', 'name' => '<script>active()</script>', 'url' => 'https://cwe.mitre.org/data/definitions/79.html']]];
    app(CveNowService::class)->saveReport($server, ['checked_at' => now()->toIso8601String(), 'packages_checked' => 1, 'containers' => [], 'runtimes' => [], 'findings' => [$finding], 'reviewed_findings' => [[...$finding,
        'cwes' => [['id' => 'CWE-89', 'name' => '<script>reviewed()</script>', 'url' => 'https://cwe.mitre.org/data/definitions/89.html']],
        'review' => ['fingerprint' => str_repeat('a', 64), 'status' => 'Not affected', 'reason' => 'Vendor review', 'source' => 'https://example.com/review'],
    ]]]);

    Livewire::test(Vulnerabilities::class, ['server_uuid' => $server->uuid])
        ->assertSee('CWE-79')->assertSee('CWE-89')->assertSee('CWE terms of use')
        ->assertSee('&lt;script&gt;active()&lt;/script&gt;', escape: false)
        ->assertSee('&lt;script&gt;reviewed()&lt;/script&gt;', escape: false)
        ->assertDontSee('<script>active()</script>', escape: false)
        ->assertDontSee('<script>reviewed()</script>', escape: false);
});

it('saves the core report and notification markers before optional CWE enrichment', function () {
    Storage::fake('local');
    $server = cveMonitoringServer();
    Notification::fake();
    $server->team->discordNotificationSettings()->updateOrCreate([], ['discord_enabled' => true, 'discord_webhook_url' => 'https://discord.com/api/webhooks/test/test', 'server_patch_discord_notifications' => true]);
    Http::preventStrayRequests();
    Http::fake([
        'cve.now/stack*' => Http::response(['packages' => 1, 'entries' => [['id' => 'CVE-2026-12345', 'severity' => ['cvss' => 5.0], 'exploitation' => ['kev' => true], 'matched' => ['ecosystem' => 'npm', 'name' => 'example', 'version' => '1.0.0'], 'affected' => []]]]),
        'api.enclave.ai/v1/threats' => Http::response(['ok' => true, 'ranAt' => '2026-11-01T12:00:00Z', 'threats' => []]),
    ]);
    $service = $this->partialMock(CveNowService::class, fn ($mock) => $mock->shouldReceive('collect')->andReturn(['packages' => [['ecosystem' => 'npm', 'name' => 'example', 'version' => '1.0.0', 'container' => 'API']], 'runtimes' => [], 'containers' => [], 'warnings' => []]));
    $this->mock(CweService::class, function ($mock) use ($service, $server) {
        $mock->shouldReceive('enrich')->once()->andReturnUsing(function ($report) use ($service, $server) {
            expect($service->report($server))->toEqual($report);
            expect($report['notified'])->toHaveCount(1);
            Notification::assertSentTo($server->team, VulnerabilitiesFound::class);

            return [...$report, 'warnings' => ['CWE lookup unavailable']];
        });
    });

    (new ServerVulnerabilityCheckJob($server))->handle($service);

    expect($service->report($server)['error'])->toBeNull();
    expect($service->report($server)['findings'][0]['known_exploited'])->toBeTrue();
    expect($service->report($server)['warnings'])->toBe(['CWE lookup unavailable']);
    Notification::assertSentTimes(VulnerabilitiesFound::class, 1);
});

it('keeps verified fixes visible and escapes their review evidence', function () {
    Storage::fake('local');
    $server = cveMonitoringServer();
    app(CveNowService::class)->saveReport($server, ['checked_at' => now()->toIso8601String(), 'packages_checked' => 0, 'runtimes' => [], 'containers' => [], 'findings' => [], 'reviewed_findings' => [[
        'id' => 'CVE-2026-12345', 'package' => 'example', 'version' => '1.0.0', 'contexts' => ['API'],
        'review' => ['fingerprint' => str_repeat('a', 64), 'status' => 'Verified image backport', 'reason' => '<script>bad()</script>', 'source' => 'https://example.com/advisory'],
    ]]]);

    Livewire::test(Vulnerabilities::class, ['server_uuid' => $server->uuid])
        ->assertSee('Verified image backport')
        ->assertSee('&lt;script&gt;bad()&lt;/script&gt;', escape: false)
        ->assertDontSee('<script>bad()</script>', escape: false);
});

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
    app(CveNowService::class)->saveReport($server, ['checked_at' => now()->toIso8601String(), 'packages_checked' => 1, 'containers' => [], 'runtimes' => [], 'enclave_updated_at' => now()->toIso8601String(), 'findings' => [['id' => 'CVE-2026-12345', 'title' => '<script>alert(1)</script>', 'score' => 9.1, 'package' => 'example', 'version' => '1.0.0', 'ecosystem' => 'npm', 'contexts' => ['api'], 'kind' => 'Package version match', 'fixed' => ['1.0.1'], 'url' => 'https://cve.now/CVE-2026-12345', 'enclave' => ['url' => 'https://app.enclave.ai/threat-feed/CVE-2026-12345', 'stage' => 'reported', 'ransomware' => true]]]]);

    Livewire::test(Vulnerabilities::class, ['server_uuid' => $server->uuid])
        ->assertSee('&lt;script&gt;alert(1)&lt;/script&gt;', escape: false)
        ->assertDontSee('<script>alert(1)</script>', escape: false)
        ->assertSee('Enclave feed refreshed')
        ->assertSee('Exploitation reported, unconfirmed')
        ->assertSee('Ransomware use reported.')
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

it('preserves positive exploitation signals and alerts when resolving low severity runtime aliases', function (bool $cveExploited, string $stage, bool $expectedExploited) {
    Storage::fake('local');
    $server = cveMonitoringServer();
    Notification::fake();
    $server->team->discordNotificationSettings()->updateOrCreate([], ['discord_enabled' => true, 'discord_webhook_url' => 'https://discord.com/api/webhooks/test/test', 'server_patch_discord_notifications' => true]);
    Http::preventStrayRequests();
    Http::fake([
        'cve.now/feed*' => Http::response(['items' => [['id' => 'GHSA-abcd-1234-5678']]]),
        'cve.now/api/v1/entries/GHSA-abcd-1234-5678' => Http::response(['id' => 'GHSA-abcd-1234-5678', 'severity' => ['cvss' => 5.0], 'exploitation' => ['kev' => $cveExploited], 'affected' => [['product' => 'php', 'ranges' => []]]]),
        'api.enclave.ai/v1/threats' => Http::response(['ok' => true, 'ranAt' => '2026-11-01T12:00:00Z', 'threats' => [[
            'cveId' => 'CVE-2026-12345', 'aliases' => ['GHSA-abcd-1234-5678'], 'name' => 'PHP issue', 'cvss' => 5.0,
            'products' => ['PHP'], 'affected' => [], 'stage' => $stage, 'updatedAt' => '2026-11-01T12:00:00Z',
        ]]]),
        'raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/12xxx/CVE-2026-12345.json' => Http::response([
            'cveMetadata' => ['cveId' => 'CVE-2026-12345', 'state' => 'PUBLISHED'],
            'containers' => ['cna' => ['affected' => [['product' => 'PHP', 'versions' => [['status' => 'affected', 'version' => '8.4.0', 'lessThan' => '8.4.27']]]]]],
        ]),
        'www.php.net/releases/*' => Http::response(['version' => '8.4.27']),
    ]);
    $service = $this->partialMock(CveNowService::class, fn ($mock) => $mock->shouldReceive('collect')->andReturn(['packages' => [], 'runtimes' => [['name' => 'php', 'version' => '8.4.26', 'container' => 'control']], 'containers' => [], 'warnings' => []]));

    (new ServerVulnerabilityCheckJob($server))->handle($service);

    $report = $service->report($server);
    expect($report['error'])->toBeNull();
    expect($report['findings'])->toHaveCount(1);
    expect($report['findings'][0])->toMatchArray(['id' => 'GHSA-abcd-1234-5678', 'kind' => 'Runtime version range match', 'score' => 5.0]);
    Notification::assertSentTimes(VulnerabilitiesFound::class, $expectedExploited ? 1 : 0);
    expect($report['findings'][0]['known_exploited'])->toBe($expectedExploited);
    expect($report['notified'])->toHaveCount($expectedExploited ? 1 : 0);
    Http::assertSentCount(5);
})->with([
    'CVE.now exploited, Enclave unconfirmed' => [true, 'reported', true],
    'CVE.now exploited, Enclave public exploit' => [true, 'exploit_public', true],
    'Enclave alone confirms exploitation' => [false, 'exploited', true],
    'neither source confirms exploitation' => [false, 'reported', false],
]);

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

it('renders detected software and security recommendations with escaped resource names', function () {
    Storage::fake('local');
    $server = cveMonitoringServer();
    Http::preventStrayRequests();
    Http::fake(['api.github.com/repos/nodejs/node/releases*' => Http::response([['tag_name' => 'v24.22.1']])]);
    $resource = '<script>private-app()</script>';
    $inventory = ['runtimes' => [['name' => 'node', 'version' => '24.22.0', 'container' => $resource]], 'containers' => [['name' => 'container-id', 'resource' => $resource, 'image' => 'app:deployed']], 'host' => ['os' => 'Ubuntu 24.04', 'kernel' => '6.8.0']];
    $finding = ['id' => 'CVE-2026-12345', 'package' => 'example', 'ecosystem' => 'npm', 'version' => '1.0.0', 'fixed' => ['1.0.1'], 'contexts' => [$resource], 'score' => 7.5, 'kind' => 'Package version match', 'url' => 'https://cve.now/CVE-2026-12345'];
    $recommendations = app(SoftwareRecommendationService::class)->recommend($inventory, [$finding]);
    app(CveNowService::class)->saveReport($server, [...$recommendations, 'checked_at' => now()->toIso8601String(), 'packages_checked' => 1, 'containers' => $inventory['containers'], 'runtimes' => $inventory['runtimes'], 'findings' => []]);

    Livewire::test(Vulnerabilities::class, ['server_uuid' => $server->uuid])
        ->assertSee('Node.js 24.22.0')->assertSee('Vendor target: 24.22.1')
        ->assertSee('Candidate: 1.0.1')->assertSee('Ubuntu 24.04')
        ->assertSee('&lt;script&gt;private-app()&lt;/script&gt;', escape: false)
        ->assertDontSee('<script>private-app()</script>', escape: false);
    Http::assertSentCount(1);
});

it('keeps software recommendations visible when vulnerability lookup is unavailable', function (bool $hasPrevious) {
    Storage::fake('local');
    Sleep::fake();
    $server = cveMonitoringServer();
    Notification::fake();
    Http::preventStrayRequests();
    Http::fake([
        'api.github.com/repos/nodejs/node/releases*' => Http::response([['tag_name' => 'v24.22.1']]),
        'cve.now/feed*' => Http::response([], 503),
    ]);
    $service = $this->partialMock(CveNowService::class, fn ($mock) => $mock->shouldReceive('collect')->andReturn(['packages' => [], 'runtimes' => [['name' => 'node', 'version' => '24.22.0', 'container' => 'Melody']], 'containers' => [], 'warnings' => []]));
    if ($hasPrevious) {
        $service->saveReport($server, ['checked_at' => '2026-10-01T00:00:00Z', 'packages_checked' => 0, 'containers' => [], 'runtimes' => [], 'findings' => []]);
    }

    (new ServerVulnerabilityCheckJob($server))->handle($service);

    $report = $service->report($server);
    expect($report['software'][0])->toMatchArray(['target' => '24.22.1', 'contexts' => ['Melody']]);
    expect($report['error'])->not->toBeEmpty();
    expect($report['inventory_checked_at'])->not->toBeEmpty();
    expect($report['checked_at'] ?? null)->toBe($hasPrevious ? '2026-10-01T00:00:00Z' : null);
    Livewire::test(Vulnerabilities::class, ['server_uuid' => $server->uuid])->assertSee('Vendor target: 24.22.1')->assertSee('Software inventory checked');
    Notification::assertNothingSent();
    Http::assertSentCount(4);
    Sleep::assertSleptTimes(2);
    Sleep::fake(false);
})->with(['previous report' => true, 'first scan' => false]);
