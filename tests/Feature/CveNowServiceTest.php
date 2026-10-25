<?php

use App\Models\Server;
use App\Services\CveNowService;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Storage;
use Symfony\Component\Process\Process;

it('collects inventory through the non-root sudo command parser', function () {
    $root = sys_get_temp_dir().'/cve-inventory-'.bin2hex(random_bytes(8));
    mkdir($root, 0700);
    file_put_contents($root.'/sudo', "#!/bin/sh\nexec \"\$@\"\n");
    file_put_contents($root.'/docker', "#!/bin/sh\nif [ \"\$1\" = version ]; then printf 29.9.2; fi\n");
    chmod($root.'/sudo', 0700);
    chmod($root.'/docker', 0700);
    try {
        $server = Mockery::mock(Server::class)->makePartial();
        $server->shouldReceive('getAttribute')->with('user')->andReturn('ubuntu');
        $server->shouldReceive('setAttribute')->andReturnSelf();
        $command = app(CveNowService::class)->inventoryCommand();
        $parsed = parseCommandsByLineForSudo(collect([$command]), $server);
        expect($parsed)->toHaveCount(1);
        $process = new Process(['/bin/bash', '-c', $parsed[0]], env: ['PATH' => $root.':'.getenv('PATH')]);
        $process->mustRun();
        $inventory = json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
        expect($inventory['packages'])->toBe([])->and($inventory['runtimes'][0]['version'])->toBe('29.9.2');
    } finally {
        unlink($root.'/sudo');
        unlink($root.'/docker');
        rmdir($root);
    }
});

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
    $server = new Server;
    $server->uuid = 'test-server';
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

it('does not follow advisory redirects to internal hosts', function () {
    Http::preventStrayRequests();
    Http::fake([
        'cve.now/feed*' => Http::response(['items' => [['id' => 'CVE-2026-12345']]]),
        'cve.now/api/v1/entries/CVE-2026-12345' => Http::response('', 302, ['Location' => 'http://127.0.0.1/secrets']),
    ]);

    expect(fn () => app(CveNowService::class)->check(['packages' => [], 'runtimes' => [['name' => 'php', 'version' => '8.4.26', 'container' => 'control']]]))->toThrow(RuntimeException::class);
    Http::assertNotSent(fn ($request) => str_contains($request->url(), '127.0.0.1'));
});

it('recognizes patched runtime releases when following the official advisory CDN', function (string $version, int $expected) {
    Http::preventStrayRequests();
    Http::fake([
        'cve.now/feed*' => Http::response(['items' => [['id' => 'CVE-2026-12345']]]),
        'cve.now/api/v1/entries/CVE-2026-12345' => Http::response('', 302, ['Location' => 'https://f9gkulwameaj0boi.public.blob.vercel-storage.com/public/entries/CVE-2026-12345.json']),
        'f9gkulwameaj0boi.public.blob.vercel-storage.com/public/entries/CVE-2026-12345.json' => Http::response(['id' => 'CVE-2026-12345', 'title' => 'Node issue', 'severity' => ['cvss' => 9.1], 'affected' => [['package' => 'node', 'ranges' => [['introduced' => '23.0.0', 'fixed' => '24.22.1']]]]]),
    ]);

    $report = app(CveNowService::class)->check(['packages' => [], 'runtimes' => [['name' => 'node', 'version' => $version, 'container' => 'api']]]);

    expect($report['findings'])->toHaveCount($expected);
})->with([['24.22.0', 1], ['24.22.1', 0]]);
