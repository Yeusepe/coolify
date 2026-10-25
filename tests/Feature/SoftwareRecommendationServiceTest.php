<?php

use App\Services\SoftwareRecommendationService;
use Illuminate\Support\Facades\Http;

it('recommends the installed Node release line instead of a newer major or prerelease', function () {
    Http::preventStrayRequests();
    Http::fake(['api.github.com/repos/nodejs/node/releases*' => Http::response([
        ['tag_name' => 'v26.12.1'], ['tag_name' => 'v24.23.0-rc.1', 'prerelease' => true], ['tag_name' => 'v24.22.1'], ['tag_name' => 'v22.23.4'],
    ])]);
    $result = app(SoftwareRecommendationService::class)->recommend(['runtimes' => [['name' => 'node', 'version' => '24.22.0', 'container' => 'Melody']]], []);

    expect($result['software'][0])->toMatchArray(['name' => 'Node.js', 'version' => '24.22.0', 'target' => '24.22.1', 'status' => 'Update available', 'contexts' => ['Melody']]);
    Http::assertSentCount(1);
});

it('identifies frameworks and keeps vendor lookup failure separate from vulnerability status', function () {
    Http::preventStrayRequests();
    Http::fake(['registry.npmjs.org/next/latest' => Http::response([], 503)]);
    $result = app(SoftwareRecommendationService::class)->recommend(['packages' => [['ecosystem' => 'npm', 'name' => 'next', 'version' => '16.4.2', 'container' => 'Creator Payments']]], []);

    expect($result['software'][0])->toMatchArray(['name' => 'Next.js', 'version' => '16.4.2', 'status' => 'Release lookup failed', 'contexts' => ['Creator Payments']]);
    Http::assertSentCount(1);
});

it('recommends stable Bun over its preview without treating preview as a released version', function () {
    Http::preventStrayRequests();
    Http::fake(['api.github.com/repos/oven-sh/bun/releases*' => Http::response([['tag_name' => 'bun-v1.4.4']])]);
    $result = app(SoftwareRecommendationService::class)->recommend(['runtimes' => [['name' => 'bun', 'version' => '1.4.4-canary.1+b1d468617', 'container' => 'Creator Payments API']]], []);

    expect($result['software'][0])->toMatchArray(['target' => '1.4.4', 'status' => 'Update available']);
    Http::assertSentCount(1);
});

it('requires review when a Bun build has the stable version label but a different source revision', function () {
    Http::preventStrayRequests();
    Http::fake([
        'api.github.com/repos/oven-sh/bun/releases*' => Http::response([['tag_name' => 'bun-v1.4.4']]),
        'api.github.com/repos/oven-sh/bun/git/ref/tags/bun-v1.4.4' => Http::response(['object' => ['type' => 'commit', 'sha' => str_repeat('a', 40)]]),
    ]);
    $result = app(SoftwareRecommendationService::class)->recommend(['runtimes' => [['name' => 'bun', 'version' => '1.4.4', 'revision' => str_repeat('b', 40), 'container' => 'Creator Payments']]], []);

    expect($result['software'][0])->toMatchArray(['target' => '1.4.4', 'status' => 'Build identity requires review']);
    Http::assertSentCount(2);
});

it('does not recommend replacing an unversioned custom binary based on a version comparison', function () {
    Http::preventStrayRequests();
    Http::fake(['api.github.com/repos/minio/minio/releases*' => Http::response([['tag_name' => 'RELEASE.2026-10-17T13-05-03Z']])]);
    $result = app(SoftwareRecommendationService::class)->recommend(['runtimes' => [['name' => 'minio', 'version' => 'DEVELOPMENT.GOGET', 'container' => 'Payments object storage']]], []);

    expect($result['software'][0])->toMatchArray(['target' => null, 'status' => 'Build identity requires review']);
    Http::assertSentCount(1);
});

it('reads database and dotnet releases from their vendors while preserving their installed lines', function () {
    Http::preventStrayRequests();
    Http::fake([
        'www.postgresql.org/versions.rss' => Http::response('<rss><channel><item><title>18.6</title></item><item><title>17.11</title></item></channel></rss>'),
        'builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json' => Http::response(['latest-runtime' => '10.0.13']),
        'downloads.mongodb.org/current.json' => Http::response(['versions' => [['version' => '9.0.4'], ['version' => '8.0.34']]]),
    ]);
    $result = app(SoftwareRecommendationService::class)->recommend(['runtimes' => [
        ['name' => 'postgresql', 'version' => '17.6', 'container' => 'Payments database'],
        ['name' => 'dotnet', 'version' => '10.0.13', 'container' => 'VRCoplay'],
        ['name' => 'mongodb', 'version' => '8.0.30', 'container' => 'Keyfi database'],
    ]], []);
    $software = collect($result['software'])->keyBy('name');

    expect($software['PostgreSQL'])->toMatchArray(['target' => '17.11', 'status' => 'Update available']);
    expect($software['ASP.NET Core'])->toMatchArray(['target' => '10.0.13', 'status' => 'No newer release found']);
    expect($software['MongoDB'])->toMatchArray(['target' => '8.0.34', 'status' => 'Update available']);
    Http::assertSentCount(3);
});

it('groups security fixes by package and flags major upgrades for migration review', function () {
    $findings = [
        ['id' => 'CVE-2026-12345', 'package' => 'undici', 'ecosystem' => 'npm', 'version' => '6.28.1', 'fixed' => ['6.29.1', '7.30.1'], 'contexts' => ['Keyfi A'], 'score' => 7.5, 'kind' => 'Package version match', 'url' => 'https://cve.now/CVE-2026-12345'],
        ['id' => 'CVE-2026-12346', 'package' => 'undici', 'ecosystem' => 'npm', 'version' => '6.28.1', 'fixed' => ['6.30.0', '7.31.0'], 'contexts' => ['Keyfi B'], 'score' => 5.9, 'kind' => 'Package version match', 'url' => 'https://cve.now/CVE-2026-12346'],
        ['id' => 'CVE-2026-12347', 'package' => 'fastify', 'ecosystem' => 'npm', 'version' => '4.29.1', 'fixed' => ['5.12.5'], 'contexts' => ['Payments metadata'], 'score' => 7.5, 'kind' => 'Package version match', 'url' => 'https://cve.now/CVE-2026-12347'],
        ['id' => 'CVE-2026-12348', 'package' => 'xlsx', 'ecosystem' => 'npm', 'version' => '0.20.2', 'fixed' => [], 'contexts' => ['Creator Payments'], 'score' => 7.8, 'kind' => 'Package version match', 'url' => 'https://cve.now/CVE-2026-12348'],
    ];
    $updates = collect(app(SoftwareRecommendationService::class)->recommend([], $findings)['package_updates'])->keyBy('package');

    expect($updates['undici'])->toMatchArray(['target' => '6.30.0', 'status' => 'Review security update', 'contexts' => ['Keyfi A', 'Keyfi B']]);
    expect($updates['fastify'])->toMatchArray(['target' => '5.12.5', 'status' => 'Migration review required']);
    expect($updates['xlsx'])->toMatchArray(['target' => null, 'status' => 'Vendor review required']);
});
