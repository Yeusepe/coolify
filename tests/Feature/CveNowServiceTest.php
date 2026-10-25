<?php

use App\Models\Server;
use App\Services\CveNowService;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Storage;

it('matches installed package versions without exporting container settings', function () {
    Http::preventStrayRequests();
    Http::fake(['cve.now/stack*' => Http::response(['packages' => 1, 'entries' => [[
        'id' => 'CVE-2026-12345', 'title' => '<script>untrusted</script>', 'severity' => ['cvss' => 9.1],
        'matched' => ['ecosystem' => 'npm', 'name' => 'example', 'version' => '1.0.0'],
        'affected' => [['ecosystem' => 'npm', 'package' => 'example', 'ranges' => [['introduced' => '0', 'fixed' => '1.0.1']]]],
    ]]])]);
    $inventory = ['packages' => [['ecosystem' => 'npm', 'name' => 'example', 'version' => '1.0.0', 'container' => 'api']], 'runtimes' => [], 'warnings' => []];

    $report = app(CveNowService::class)->check($inventory);

    expect($report['findings'])->toHaveCount(1)
        ->and($report['findings'][0]['fixed'])->toBe(['1.0.1'])
        ->and($report['findings'][0]['contexts'])->toBe(['api'])
        ->and($report['findings'][0]['url'])->toBe('https://cve.now/CVE-2026-12345');
    Http::assertSent(fn ($request) => $request->url() === 'https://cve.now/stack?p=npm%3Aexample%401.0.0&format=json');
});

it('does not interpret an invalid upstream response as a clean report', function () {
    Http::preventStrayRequests();
    Http::fake(['cve.now/stack*' => Http::response(['packages' => 1])]);

    expect(fn () => app(CveNowService::class)->check(['packages' => [['ecosystem' => 'npm', 'name' => 'example', 'version' => '1.0.0', 'container' => 'api']], 'runtimes' => []]))
        ->toThrow(RuntimeException::class);
});

it('rejects upstream matches for a version that was not submitted', function () {
    Http::preventStrayRequests();
    Http::fake(['cve.now/stack*' => Http::response(['packages' => 1, 'entries' => [[
        'id' => 'CVE-2026-12345', 'matched' => ['ecosystem' => 'npm', 'name' => 'example', 'version' => '0.0.1'],
    ]]])]);

    expect(fn () => app(CveNowService::class)->check(['packages' => [['ecosystem' => 'npm', 'name' => 'example', 'version' => '1.0.0', 'container' => 'api']], 'runtimes' => []]))
        ->toThrow(RuntimeException::class);
});

it('retains a previous report when discovery or the feed fails', function () {
    Storage::fake('local');
    $server = Server::factory()->make(['uuid' => 'test-server']);
    $service = app(CveNowService::class);
    $service->saveReport($server, ['checked_at' => '2026-10-01T00:00:00Z', 'findings' => [['id' => 'CVE-2026-12345']]]);

    $service->recordFailure($server);

    expect($service->report($server)['findings'][0]['id'])->toBe('CVE-2026-12345')
        ->and($service->report($server)['error'])->not->toBeEmpty();
});

it('compares runtime ranges against the installed release rather than the latest major', function () {
    $service = app(CveNowService::class);

    expect($service->inRanges('24.22.0', [['introduced' => '23.0.0', 'fixed' => '24.22.1']]))->toBeTrue()
        ->and($service->inRanges('24.22.1', [['introduced' => '23.0.0', 'fixed' => '24.22.1']]))->toBeFalse()
        ->and($service->inRanges('22.23.4', [['introduced' => '23.0.0', 'fixed' => '24.22.1']]))->toBeFalse()
        ->and($service->inRanges('1.2.0', [['introduced' => '0', 'lastAffected' => '1.2.0']]))->toBeTrue()
        ->and($service->inRanges('dev-main', [['introduced' => '0', 'fixed' => '2.0.0']]))->toBeNull();
});

it('validates additional package names and exact versions', function () {
    $service = app(CveNowService::class);

    expect($service->parsePackages('npm:@scope/example@1.2.3'))->toBe([['ecosystem' => 'npm', 'name' => '@scope/example', 'version' => '1.2.3', 'container' => 'Additional technology']]);
    expect(fn () => $service->parsePackages('npm:example@https://user:password@internal'))->toThrow(InvalidArgumentException::class);
});
