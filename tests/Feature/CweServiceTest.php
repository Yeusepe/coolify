<?php

use App\Services\CweService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

function cwePublishedRecord(array $overrides = []): array
{
    return array_replace_recursive([
        'cveMetadata' => ['cveId' => 'CVE-2026-12345', 'state' => 'PUBLISHED'],
        'containers' => ['cna' => ['problemTypes' => [['descriptions' => [['cweId' => 'CWE-79']]]]]],
    ], $overrides);
}

it('adds cached official CWE labels to active and reviewed advisories without changing vulnerability evidence', function () {
    Http::preventStrayRequests();
    Http::fake([
        'raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/12xxx/CVE-2026-12345.json' => Http::response(cwePublishedRecord(['containers' => ['adp' => [['problemTypes' => [['descriptions' => [['cweId' => 'CWE-79'], ['cweId' => 'CWE-89'], ['cweId' => 'NVD-CWE-noinfo'], ['cweId' => 'CWE-../../secrets']]]]]]]])),
        'cwe-api.mitre.org/api/v1/cwe/weakness/79' => Http::response(['Weaknesses' => [['ID' => '79', 'Name' => 'Cross-site Scripting']]]),
        'cwe-api.mitre.org/api/v1/cwe/weakness/89' => Http::response(['Weaknesses' => [['ID' => '89', 'Name' => 'SQL Injection']]]),
    ]);
    $finding = ['id' => 'GHSA-abcd-1234-5678', 'cve_ids' => ['CVE-2026-12345', '../../secrets'], 'known_exploited' => true, 'score' => 5.0, 'kind' => 'Runtime version range match', 'fixed' => ['8.4.27'], 'contexts' => ['API']];
    $report = ['findings' => [$finding], 'reviewed_findings' => [[...$finding, 'review' => ['status' => 'Not affected']]], 'notified' => ['existing-notification'], 'error' => null];
    $service = app(CweService::class);

    $enriched = $service->enrich($report);
    $service->enrich($report);

    $expected = [['id' => 'CWE-79', 'name' => 'Cross-site Scripting', 'url' => 'https://cwe.mitre.org/data/definitions/79.html'], ['id' => 'CWE-89', 'name' => 'SQL Injection', 'url' => 'https://cwe.mitre.org/data/definitions/89.html']];
    expect($enriched)->toBe([...$report, 'findings' => [[...$finding, 'cwes' => $expected]], 'reviewed_findings' => [[...$report['reviewed_findings'][0], 'cwes' => $expected]]]);
    Http::assertSentCount(3);
    Http::assertSent(fn ($request) => $request->url() === 'https://cwe-api.mitre.org/api/v1/cwe/weakness/79' && $request->method() === 'GET' && $request->data() === []);
});

it('resolves an Enclave CVE alias and reuses the existing verified CVE record cache', function () {
    Http::preventStrayRequests();
    Cache::put('cve-now:primary:CVE-2026-12345', cwePublishedRecord(), 3600);
    Http::fake(['cwe-api.mitre.org/api/v1/cwe/weakness/79' => Http::response(['Weaknesses' => [['ID' => '79', 'Name' => 'Cross-site Scripting']]])]);

    $enriched = app(CweService::class)->enrich(['findings' => [['id' => 'GHSA-abcd-1234-5678', 'enclave' => ['id' => 'CVE-2026-12345']]]]);

    expect($enriched['findings'][0]['cwes'][0]['id'])->toBe('CWE-79');
    Http::assertSentCount(1);
});

it('does not infer CVE identities or CWEs from unverified identifiers or advisory text', function () {
    Http::preventStrayRequests();
    $report = ['findings' => [['id' => '../../secrets', 'cve_ids' => ['CVE-2026-../secrets'], 'title' => 'CWE-79 and CVE-2026-12345'], ['id' => 'ZDI-CAN-33367'], ['id' => 'GHSA-abcd-1234-5678']]];

    expect(app(CweService::class)->enrich($report))->toBe($report);

    Http::assertNothingSent();
});

it('retains vulnerability results with a warning when the CVE mapping cannot be verified', function (array|string $body, int $status) {
    Http::preventStrayRequests();
    Http::fake(['raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/12xxx/CVE-2026-12345.json' => Http::response($body, $status, ['Location' => 'http://127.0.0.1/secrets'])]);
    $finding = ['id' => 'CVE-2026-12345', 'known_exploited' => true, 'score' => 5.0];

    $enriched = app(CweService::class)->enrich(['findings' => [$finding], 'notified' => ['already-sent'], 'error' => null]);

    expect($enriched)->toMatchArray(['findings' => [$finding], 'notified' => ['already-sent'], 'error' => null]);
    expect($enriched['warnings'])->toBe(['Some CWE classifications could not be loaded. Vulnerability matches and alerts are unchanged.']);
    Http::assertSentCount(1);
})->with([
    'unavailable' => [[], 503],
    'redirect' => [[], 302],
    'invalid JSON' => ['not-json', 200],
    'mismatched CVE' => [cwePublishedRecord(['cveMetadata' => ['cveId' => 'CVE-2026-99999']]), 200],
    'rejected CVE' => [cwePublishedRecord(['cveMetadata' => ['state' => 'REJECTED']]), 200],
]);

it('retains mapped CWE IDs without inventing a name when the MITRE catalogue is unavailable or mismatched', function (array $body, int $status) {
    Http::preventStrayRequests();
    Cache::put('cve-now:primary:CVE-2026-12345', cwePublishedRecord(), 3600);
    Http::fake(['cwe-api.mitre.org/api/v1/cwe/weakness/79' => Http::response($body, $status, ['Location' => 'http://127.0.0.1/secrets'])]);

    $enriched = app(CweService::class)->enrich(['findings' => [['id' => 'CVE-2026-12345', 'known_exploited' => true]]]);

    expect($enriched['findings'][0])->toMatchArray(['known_exploited' => true, 'cwes' => [['id' => 'CWE-79', 'name' => null, 'url' => 'https://cwe.mitre.org/data/definitions/79.html']]]);
    expect($enriched['warnings'])->toHaveCount(1);
    Http::assertSentCount(1);
})->with([
    'unavailable' => [[], 503],
    'redirect' => [[], 302],
    'mismatched weakness' => [['Weaknesses' => [['ID' => '89', 'Name' => 'SQL Injection']]], 200],
    'missing name' => [['Weaknesses' => [['ID' => '79']]], 200],
]);

it('leaves an unclassified CVE without fabricated labels', function () {
    Http::preventStrayRequests();
    Cache::put('cve-now:primary:CVE-2026-12345', ['cveMetadata' => ['cveId' => 'CVE-2026-12345', 'state' => 'PUBLISHED'], 'containers' => ['cna' => []]], 3600);

    $enriched = app(CweService::class)->enrich(['findings' => [['id' => 'CVE-2026-12345']]]);

    expect($enriched['findings'][0]['cwes'])->toBe([]);
    expect($enriched)->not->toHaveKey('warnings');
    Http::assertNothingSent();
});

it('continues classifying other advisories when one CVE lookup fails', function () {
    Http::preventStrayRequests();
    Cache::put('cve-now:primary:CVE-2026-12346', cwePublishedRecord(['cveMetadata' => ['cveId' => 'CVE-2026-12346']]), 3600);
    Http::fake([
        'raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/12xxx/CVE-2026-12345.json' => Http::response([], 503),
        'cwe-api.mitre.org/api/v1/cwe/weakness/79' => Http::response(['Weaknesses' => [['ID' => '79', 'Name' => 'Cross-site Scripting']]]),
    ]);

    $enriched = app(CweService::class)->enrich(['findings' => [['id' => 'CVE-2026-12345'], ['id' => 'CVE-2026-12346']]]);

    expect($enriched['findings'][1])->toMatchArray(['cwes' => [['id' => 'CWE-79', 'name' => 'Cross-site Scripting', 'url' => 'https://cwe.mitre.org/data/definitions/79.html']]]);
    expect($enriched['warnings'])->toHaveCount(1);
    Http::assertSentCount(2);
});
