<?php

use App\Jobs\ServerSourceScanJob;
use App\Livewire\Server\Security\SourceScanning;
use App\Models\Application;
use App\Models\Environment;
use App\Models\InstanceSettings;
use App\Models\Project;
use App\Models\Server;
use App\Models\StandaloneDocker;
use App\Models\Team;
use App\Models\User;
use App\Services\SourceScanService;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Livewire\Livewire;

uses(RefreshDatabase::class);

function sourceScanningServer(string $role = 'owner'): Server
{
    Server::flushIdentityMap();
    Storage::fake('local');
    InstanceSettings::forceCreate(['id' => 0]);
    $team = Team::factory()->create();
    $user = User::factory()->create();
    $team->members()->attach($user->id, ['role' => $role]);
    test()->actingAs($user);
    session(['currentTeam' => $team]);
    config(['services.source_scanning.enabled' => true]);

    return Server::factory()->create(['team_id' => $team->id]);
}

it('shows escaped findings and coalesces manual source scans', function () {
    $server = sourceScanningServer();
    Queue::fake([ServerSourceScanJob::class]);
    app(SourceScanService::class)->saveReport($server, ['repositories' => [[
        'id' => 'test', 'repository' => 'owner/app', 'status' => 'partial', 'ref' => 'main', 'ref_kind' => 'Configured reference', 'commit' => str_repeat('a', 40), 'applications' => ['API'],
        'findings' => [['path' => 'app.ts', 'line' => 1, 'severity' => 'WARNING', 'fingerprint' => 'fixture', 'message' => '<script>secret()</script>', 'rule_url' => 'https://gitlab.com/example/rule', 'cwes' => ['CWE-95']]],
    ]]]);
    Livewire::test(SourceScanning::class, ['server_uuid' => $server->uuid])
        ->assertSee('CWE-95')->assertSee('Coverage is incomplete')
        ->assertSee('&lt;script&gt;secret()&lt;/script&gt;', escape: false)
        ->assertDontSee('<script>secret()</script>', escape: false)
        ->call('scan')->call('scan');
    Queue::assertPushed(ServerSourceScanJob::class, 1);
});

it('forbids a member from reading or requesting source scans', function () {
    $server = sourceScanningServer('member');
    Livewire::test(SourceScanning::class, ['server_uuid' => $server->uuid])->assertForbidden();
});

it('does not disclose another teams source findings', function () {
    sourceScanningServer();
    $other = Server::factory()->create(['team_id' => Team::factory()->create()->id]);
    expect(fn () => Livewire::test(SourceScanning::class, ['server_uuid' => $other->uuid]))->toThrow(ModelNotFoundException::class);
});

it('uses the resource team after a session switches and refuses a revoked role', function () {
    $server = sourceScanningServer();
    $component = Livewire::test(SourceScanning::class, ['server_uuid' => $server->uuid]);
    $other = Team::factory()->create();
    $other->members()->attach(auth()->id(), ['role' => 'member']);
    session(['currentTeam' => $other]);
    Queue::fake([ServerSourceScanJob::class]);
    $component->call('scan')->assertSuccessful();
    Queue::assertPushed(ServerSourceScanJob::class, fn ($job) => $job->server->id === $server->id);
    $server->team->members()->updateExistingPivot(auth()->id(), ['role' => 'member']);
    auth()->user()->unsetRelation('teams');
    $component->call('scan')->assertForbidden();
});

it('scans only the server owning teams apps and deduplicates matching references', function () {
    $server = sourceScanningServer();
    $project = Project::factory()->create(['team_id' => $server->team_id]);
    $environment = Environment::factory()->create(['project_id' => $project->id]);
    $destination = $server->standaloneDockers()->firstOrFail();
    $attributes = ['environment_id' => $environment->id, 'destination_id' => $destination->id, 'destination_type' => StandaloneDocker::class, 'git_repository' => 'owner/app', 'git_branch' => 'main', 'git_commit_sha' => 'HEAD', 'private_key_id' => null, 'source_id' => null, 'source_type' => null];
    Application::factory()->create([...$attributes, 'name' => 'API']);
    Application::factory()->create([...$attributes, 'name' => 'Worker']);
    $foreignProject = Project::factory()->create(['team_id' => Team::factory()->create()->id]);
    $foreignEnvironment = Environment::factory()->create(['project_id' => $foreignProject->id]);
    Application::factory()->create([...$attributes, 'name' => 'FOREIGN_PRIVATE', 'environment_id' => $foreignEnvironment->id]);
    $inventory = app(SourceScanService::class)->targets($server);
    expect($inventory['targets'])->toHaveCount(1);
    expect($inventory['targets'][0]['applications'])->toBe(['API', 'Worker']);
    expect(json_encode($inventory))->not->toContain('FOREIGN_PRIVATE');
});

it('retains the last source report when the remote scan fails', function () {
    $server = sourceScanningServer();
    $server->settings->update(['is_reachable' => true, 'is_usable' => true, 'force_disabled' => false]);
    $service = $this->partialMock(SourceScanService::class, fn ($mock) => $mock->shouldReceive('collect')->once()->andThrow(new RuntimeException('PRIVATE_TOKEN')));
    $service->saveReport($server, ['repositories' => [['id' => 'old', 'findings' => [['path' => 'app.ts']]]]]);
    (new ServerSourceScanJob($server))->handle($service);
    expect($service->report($server)['repositories'][0]['id'])->toBe('old');
    expect(json_encode($service->report($server)))->not->toContain('PRIVATE_TOKEN');
});
