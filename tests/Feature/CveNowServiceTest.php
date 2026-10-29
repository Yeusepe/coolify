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

it('detects database and proxy versions and preserves the actual Bun prerelease', function (string $minioVersion) {
    $root = sys_get_temp_dir().'/cve-software-'.bin2hex(random_bytes(8));
    mkdir($root, 0700);
    file_put_contents($root.'/docker', str_replace('MINIO_BUILD_VERSION', $minioVersion, <<<'SH'
#!/bin/sh
case "$1 $2 $3 $4" in
  'version --format {{.Server.Version}} ') printf 29.9.2 ;;
  'ps --format '*) printf 'container|app|test-image\n' ;;
  'exec container node -e') printf '%s' '{"packages":[],"runtime":{"name":"bun","version":"1.4.4"}}' ;;
  'exec container bun --version') printf '1.4.4-canary.1+b1d468617' ;;
  'exec container sh -c') case "$5" in
    *CVE_SOFTWARE_*) printf '\nCVE_SOFTWARE_postgresql\npostgres (PostgreSQL) 17.6\nCVE_SOFTWARE_redis\nRedis server v=7.4.8 sha=000\nCVE_SOFTWARE_nginx\nnginx version: nginx/1.31.8\nCVE_SOFTWARE_openssl\nOpenSSL 3.5.6\nCVE_SOFTWARE_minio\nminio version MINIO_BUILD_VERSION\nRuntime: go1.27.3 linux/amd64\nCVE_SOFTWARE_postgrest\nPostgREST 14.18\n' ;;
  esac ;;
esac
SH));
    chmod($root.'/docker', 0700);
    try {
        $process = new Process(['/bin/bash', '-c', app(CveNowService::class)->inventoryCommand()], env: ['PATH' => $root.':'.getenv('PATH')]);
        $process->mustRun();
        $inventory = json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
        $runtimes = collect($inventory['runtimes'])->keyBy('name');

        expect($runtimes['bun']['version'])->toBe('1.4.4-canary.1+b1d468617');
        expect($runtimes['postgresql']['version'])->toBe('17.6');
        expect($runtimes['redis']['version'])->toBe('7.4.8');
        expect($runtimes['nginx']['version'])->toBe('1.31.8');
        expect($runtimes['openssl']['version'])->toBe('3.5.6');
        expect($runtimes['minio']['version'])->toBe($minioVersion);
        expect($runtimes['go']['version'])->toBe('1.27.3');
        expect($runtimes['postgrest']['version'])->toBe('14.18');
    } finally {
        unlink($root.'/docker');
        rmdir($root);
    }
})->with(['DEVELOPMENT.GOGET', 'RACCONIFY.20261025']);

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

it('handles wildcard branches used by live runtime advisories', function () {
    $service = app(CveNowService::class);
    $phpRanges = [['introduced' => '8.2.*', 'fixed' => '8.2.35'], ['introduced' => '8.3.*', 'fixed' => '8.3.36'], ['introduced' => '8.4.*', 'fixed' => '8.4.27'], ['introduced' => '8.5.*', 'fixed' => '8.5.12']];
    expect($service->inRanges('8.4.27', $phpRanges))->toBeFalse()
        ->and($service->inRanges('8.4.26', $phpRanges))->toBeTrue()
        ->and($service->inRanges('24.22.1', [['introduced' => '*', 'lastAffected' => '21.7.2']]))->toBeFalse()
        ->and($service->inRanges('24.22.1', [['introduced' => '4.0', 'fixed' => '4.*'], ['introduced' => '24.14.0', 'lastAffected' => '24.14.0']]))->toBeFalse()
        ->and($service->inRanges('24.14.0', [['introduced' => '4.0', 'fixed' => '4.*'], ['introduced' => '24.14.0', 'lastAffected' => '24.14.0']]))->toBeTrue()
        ->and($service->inRanges('4.5.0', [['introduced' => '4.0', 'fixed' => '4.*']]))->toBeNull()
        ->and($service->inRanges('8.5.0', [['introduced' => '8.4.*']]))->toBeFalse();
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

it('restores missing release boundaries from the published CNA record', function (string $installed, int $expected) {
    Http::preventStrayRequests();
    Http::fake([
        'cve.now/feed*' => Http::response(['items' => [['id' => 'CVE-2026-12345']]]),
        'cve.now/api/v1/entries/CVE-2026-12345' => Http::response(['id' => 'CVE-2026-12345', 'affected' => [['product' => 'PHP', 'ranges' => [['fixed' => '8.4.27'], ['fixed' => '8.5.12']]]]]),
        'raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/12xxx/CVE-2026-12345.json' => Http::response([
            'cveMetadata' => ['cveId' => 'CVE-2026-12345', 'state' => 'PUBLISHED'],
            'containers' => ['cna' => ['affected' => [['product' => 'PHP', 'versions' => [
                ['status' => 'affected', 'version' => '8.4.*', 'lessThan' => '8.4.27'],
                ['status' => 'affected', 'version' => '8.5.*', 'lessThan' => '8.5.12'],
            ]]]]],
        ]),
    ]);

    $report = app(CveNowService::class)->check(['packages' => [], 'runtimes' => [['name' => 'php', 'version' => $installed, 'container' => 'control']]]);

    expect($report['findings'])->toHaveCount($expected);
    Http::assertSent(fn ($request) => str_starts_with($request->url(), 'https://raw.githubusercontent.com/CVEProject/cvelistV5/'));
})->with([['8.4.26', 1], ['8.4.27', 0], ['8.5.11', 1]]);

it('retains an uncertain advisory when its missing primary boundaries cannot be verified', function () {
    Http::preventStrayRequests();
    Http::fake([
        'cve.now/feed*' => Http::response(['items' => [['id' => 'CVE-2026-12345']]]),
        'cve.now/api/v1/entries/CVE-2026-12345' => Http::response(['id' => 'CVE-2026-12345', 'affected' => [['product' => 'node', 'ranges' => [['introduced' => '4.0']]]]]),
        'raw.githubusercontent.com/CVEProject/cvelistV5/*' => Http::response([], 503),
    ]);

    $report = app(CveNowService::class)->check(['packages' => [], 'runtimes' => [['name' => 'node', 'version' => '24.22.1', 'container' => 'api']]]);

    expect($report['findings'])->toHaveCount(1);
    expect($report['findings'][0]['kind'])->toBe('Technology advisory. Check vendor applicability');
    Http::assertSentCount(3);
});

it('binds a reviewed fix to the exact image and keeps it visible separately', function () {
    $service = app(CveNowService::class);
    $finding = ['id' => 'CVE-2026-12345', 'ecosystem' => 'npm', 'package' => 'example', 'version' => '1.0.0', 'contexts' => ['API']];
    $report = ['findings' => [$finding], 'containers' => [['name' => 'api', 'resource' => 'API', 'image_id' => 'sha256:'.str_repeat('a', 64)]]];
    $review = ['fingerprint' => $service->findingFingerprint($finding, $report), 'status' => 'Verified image backport', 'reason' => 'Regression-tested upstream fix.', 'source' => 'https://example.com/advisory'];

    $reviewed = $service->applyReviews($report, [$review]);

    expect($reviewed['findings'])->toBe([]);
    expect($reviewed['reviewed_findings'][0]['review'])->toBe($review);
    $report['containers'][0]['image_id'] = 'sha256:'.str_repeat('b', 64);
    expect($service->applyReviews($report, [$review])['findings'])->toBe([$finding]);
});

it('does not dismiss a finding without complete image provenance or a valid review', function () {
    $service = app(CveNowService::class);
    $finding = ['id' => 'CVE-2026-12345', 'ecosystem' => 'npm', 'package' => 'example', 'version' => '1.0.0', 'contexts' => ['API']];
    $report = ['findings' => [$finding], 'containers' => [['name' => 'api', 'resource' => 'API']]];

    expect($service->findingFingerprint($finding, $report))->toBeNull();
    expect($service->applyReviews($report, [['fingerprint' => null, 'status' => 'Verified image backport', 'reason' => 'Unverified', 'source' => 'javascript:alert(1)']])['findings'])->toBe([$finding]);
});
