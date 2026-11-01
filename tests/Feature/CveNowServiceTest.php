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
        'aliases' => ['CVE-2026-12346', 'CVE-2026-12345', '../../secrets', ['CVE-2026-12347']],
        'matched' => ['ecosystem' => 'npm', 'name' => 'example', 'version' => '1.0.0'],
        'affected' => [['ecosystem' => 'npm', 'package' => 'example', 'ranges' => [['introduced' => '0', 'fixed' => '1.0.1']]]],
    ]]])]);
    $inventory = ['packages' => [['ecosystem' => 'npm', 'name' => 'example', 'version' => '1.0.0', 'container' => 'api']], 'runtimes' => [], 'warnings' => []];

    $report = app(CveNowService::class)->check($inventory);

    expect($report['findings'])->toHaveCount(1)
        ->and($report['findings'][0]['fixed'])->toBe(['1.0.1'])
        ->and($report['findings'][0]['contexts'])->toBe(['api'])
        ->and($report['findings'][0]['cve_ids'])->toBe(['CVE-2026-12345', 'CVE-2026-12346'])
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
    expect($service->applyReviews($reviewed, [$review])['reviewed_findings'])->toHaveCount(1);
    expect($service->applyReviews($reviewed, [])['findings'])->toBe([$finding]);
    $changed = $report;
    $changed['findings'][0]['advisory_modified_at'] = '2026-10-30T00:00:00Z';
    expect($service->applyReviews($changed, [$review])['findings'])->toHaveCount(1);
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

it('keeps old Node branches bounded and accepts PostgreSQL major boundaries', function () {
    $service = app(CveNowService::class);
    expect($service->inRanges('24.22.1', [['introduced' => '4.0', 'fixed' => '4.*'], ['introduced' => '20.0', 'fixed' => '20.5.1']]))->toBeFalse()
        ->and($service->inRanges('17.2', [['introduced' => '17', 'fixed' => '17.3']]))->toBeTrue()
        ->and($service->inRanges('17.3', [['introduced' => '17', 'fixed' => '17.3']]))->toBeFalse();
});

function enclaveCveThreat(array $overrides = []): array
{
    return [...[
        'cveId' => 'CVE-2026-12345', 'aliases' => [], 'name' => 'PHP issue', 'cvss' => 9.1,
        'products' => ['PHP'], 'affected' => [['product' => 'PHP', 'versions' => 'before 8.4.99', 'fixedIn' => '8.4.99']],
        'stage' => 'exploited', 'knownRansomware' => true, 'updatedAt' => '2026-11-01T12:00:00Z',
    ], ...$overrides];
}

it('enriches matching advisory IDs and aliases without uploading inventory or duplicating findings', function (string $id, string $stage, bool $exploited) {
    Http::preventStrayRequests();
    Http::fake([
        'cve.now/stack*' => Http::response(['packages' => 1, 'entries' => [[
            'id' => $id, 'severity' => ['cvss' => 5.0],
            'matched' => ['ecosystem' => 'npm', 'name' => 'example', 'version' => '1.0.0'], 'affected' => [],
        ]]]),
        'api.enclave.ai/v1/threats' => Http::response(['ok' => true, 'ranAt' => '2026-11-01T12:00:00Z', 'threats' => [enclaveCveThreat(['aliases' => ['GHSA-abcd-1234-5678'], 'stage' => $stage]), enclaveCveThreat(['cveId' => 'ZDI-CAN-33367', 'products' => ['Linux'], 'affected' => []])]]),
    ]);
    $inventory = ['packages' => [['ecosystem' => 'npm', 'name' => 'example', 'version' => '1.0.0', 'container' => 'private-container']], 'runtimes' => []];
    $service = app(CveNowService::class);

    $report = $service->check($inventory);
    $service->check($inventory);

    expect($report['findings'])->toHaveCount(1);
    expect($report['findings'][0])->toMatchArray(['id' => $id, 'known_exploited' => $exploited, 'score' => 5.0, 'enclave' => ['url' => 'https://app.enclave.ai/threat-feed/CVE-2026-12345', 'id' => 'CVE-2026-12345', 'stage' => $stage, 'ransomware' => true]]);
    expect($report['enclave_updated_at'])->toBe('2026-11-01T12:00:00Z');
    Http::assertSent(fn ($request) => $request->url() === 'https://api.enclave.ai/v1/threats' && $request->method() === 'GET' && $request->data() === []);
    Http::assertSentCount(2);
})->with([
    'confirmed CVE' => ['CVE-2026-12345', 'exploited', true],
    'unconfirmed alias' => ['GHSA-abcd-1234-5678', 'reported', false],
    'public exploit alone' => ['CVE-2026-12345', 'exploit_public', false],
]);

it('discovers runtime threats absent from CVE.now and uses primary version boundaries rather than feed prose', function (string $version, int $count) {
    Http::preventStrayRequests();
    Http::fake([
        'cve.now/feed*' => Http::response(['items' => []]),
        'api.enclave.ai/v1/threats' => Http::response(['ok' => true, 'ranAt' => '2026-11-01T12:00:00Z', 'threats' => [enclaveCveThreat()]]),
        'raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/12xxx/CVE-2026-12345.json' => Http::response([
            'cveMetadata' => ['cveId' => 'CVE-2026-12345', 'state' => 'PUBLISHED'],
            'containers' => ['cna' => ['affected' => [['product' => 'PHP', 'versions' => [['status' => 'affected', 'version' => '8.4.0', 'lessThan' => '8.4.27']]]]]],
        ]),
    ]);

    $report = app(CveNowService::class)->check(['packages' => [], 'runtimes' => [['name' => 'php', 'version' => $version, 'container' => 'control'], ['name' => 'php', 'version' => $version, 'container' => 'api']]]);

    expect($report['findings'])->toHaveCount($count);
    if ($count) {
        expect($report['findings'][0])->toMatchArray(['kind' => 'Runtime version range match', 'fixed' => ['8.4.27'], 'contexts' => ['control', 'api'], 'url' => 'https://app.enclave.ai/threat-feed/CVE-2026-12345', 'known_exploited' => true, 'advisory_modified_at' => '2026-11-01T12:00:00Z']);
    }
    Http::assertSentCount(3);
})->with(['affected' => ['8.4.26', 1], 'fixed boundary' => ['8.4.27', 0], 'new branch' => ['8.5.12', 0]]);

it('keeps Enclave runtime threats review-only when primary boundaries cannot be verified', function () {
    Http::preventStrayRequests();
    Http::fake([
        'cve.now/feed*' => Http::response(['items' => []]),
        'api.enclave.ai/v1/threats' => Http::response(['ok' => true, 'ranAt' => '2026-11-01T12:00:00Z', 'threats' => [enclaveCveThreat()]]),
        'raw.githubusercontent.com/CVEProject/cvelistV5/*' => Http::response([], 503),
    ]);

    $report = app(CveNowService::class)->check(['runtimes' => [['name' => 'php', 'version' => '8.4.26', 'container' => 'control']]]);

    expect($report['findings'])->toHaveCount(1);
    expect($report['findings'][0])->toMatchArray(['kind' => 'Technology advisory. Check vendor applicability', 'fixed' => []]);
    Http::assertSentCount(3);
});

it('merges overlapping runtime advisories and ignores unrelated product names', function (string $id) {
    Http::preventStrayRequests();
    Http::fake([
        'cve.now/feed*' => Http::response(['items' => [['id' => $id]]]),
        'cve.now/api/v1/entries/'.$id => Http::response(['id' => $id, 'affected' => [['product' => 'php', 'ranges' => [['introduced' => '8.4.0', 'fixed' => '8.4.27']]]]]),
        'api.enclave.ai/v1/threats' => Http::response(['ok' => true, 'ranAt' => '2026-11-01T12:00:00Z', 'threats' => [enclaveCveThreat(['aliases' => ['GHSA-abcd-1234-5678']]), enclaveCveThreat(['cveId' => 'CVE-2026-12346', 'products' => ['YouPHPTube'], 'affected' => [['product' => 'YouPHPTube']]])]]),
        'raw.githubusercontent.com/CVEProject/cvelistV5/*' => Http::response([], 503),
    ]);

    $report = app(CveNowService::class)->check(['runtimes' => [['name' => 'php', 'version' => '8.4.26', 'container' => 'control']]]);

    expect($report['findings'])->toHaveCount(1);
    expect($report['findings'][0])->toMatchArray(['id' => $id, 'kind' => 'Runtime version range match', 'fixed' => ['8.4.27'], 'known_exploited' => true, 'url' => 'https://cve.now/'.$id]);
    Http::assertNotSent(fn ($request) => str_contains($request->url(), 'CVE-2026-12346'));
})->with(['same identifier' => ['CVE-2026-12345'], 'GHSA alias' => ['GHSA-abcd-1234-5678']]);

it('resolves uncertain runtime aliases using authoritative ranges discovered through Enclave', function (string $version, int $count) {
    Http::preventStrayRequests();
    Http::fake([
        'cve.now/feed*' => Http::response(['items' => [['id' => 'GHSA-abcd-1234-5678']]]),
        'cve.now/api/v1/entries/GHSA-abcd-1234-5678' => Http::response(['id' => 'GHSA-abcd-1234-5678', 'affected' => [['product' => 'php', 'ranges' => []]]]),
        'api.enclave.ai/v1/threats' => Http::response(['ok' => true, 'ranAt' => '2026-11-01T12:00:00Z', 'threats' => [enclaveCveThreat(['aliases' => ['GHSA-abcd-1234-5678']])]]),
        'raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/12xxx/CVE-2026-12345.json' => Http::response([
            'cveMetadata' => ['cveId' => 'CVE-2026-12345', 'state' => 'PUBLISHED'],
            'containers' => ['cna' => ['affected' => [['product' => 'PHP', 'versions' => [['status' => 'affected', 'version' => '8.4.0', 'lessThan' => '8.4.27']]]]]],
        ]),
    ]);

    $report = app(CveNowService::class)->check(['runtimes' => [['name' => 'php', 'version' => $version, 'container' => 'control'], ['name' => 'php', 'version' => $version, 'container' => 'api']]]);

    expect($report['findings'])->toHaveCount($count);
    if ($count) {
        expect($report['findings'][0])->toMatchArray(['id' => 'GHSA-abcd-1234-5678', 'kind' => 'Runtime version range match', 'fixed' => ['8.4.27'], 'contexts' => ['control', 'api'], 'url' => 'https://cve.now/GHSA-abcd-1234-5678', 'known_exploited' => true]);
    }
    Http::assertSentCount(4);
})->with(['confirmed affected' => ['8.4.26', 1], 'confirmed patched' => ['8.4.27', 0]]);

it('retains CVE.now findings with a visible warning when Enclave fails validation or availability', function (array $body, int $status) {
    Http::preventStrayRequests();
    Http::fake([
        'cve.now/stack*' => Http::response(['packages' => 1, 'entries' => [[
            'id' => 'CVE-2026-12345', 'matched' => ['ecosystem' => 'npm', 'name' => 'example', 'version' => '1.0.0'], 'affected' => [],
        ]]]),
        'api.enclave.ai/v1/threats' => Http::response($body, $status, ['Location' => 'http://127.0.0.1/secrets']),
    ]);

    $report = app(CveNowService::class)->check(['packages' => [['ecosystem' => 'npm', 'name' => 'example', 'version' => '1.0.0']]]);

    expect($report['findings'])->toHaveCount(1);
    expect($report['error'])->toBeNull();
    expect($report['enclave_updated_at'])->toBeNull();
    expect($report['warnings'])->toContain('Enclave threat intelligence is unavailable. CVE.now results are retained; exploitation signals may be incomplete.');
    Http::assertSentCount(2);
})->with([
    'unavailable' => [[], 503],
    'redirect' => [[], 302],
    'invalid JSON shape' => [['ok' => true, 'ranAt' => '2026-11-01T12:00:00Z'], 200],
    'invalid identifier' => [['ok' => true, 'ranAt' => '2026-11-01T12:00:00Z', 'threats' => [['cveId' => '../../secrets']]], 200],
]);
