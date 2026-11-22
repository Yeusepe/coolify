<?php

use Illuminate\Support\Facades\Http;

function cveCheckRoutes(array $entries): array
{
    return [
        'cve.now/api/v1/check' => Http::response(['checked' => 1, 'affected' => array_map(fn ($entry) => [
            'id' => $entry['id'], 'title' => $entry['title'] ?? $entry['id'],
            'severity' => $entry['severity'] ?? null, 'package' => $entry['matched'],
            'kev' => $entry['exploitation']['kev'] ?? false,
            'cves' => array_values(array_filter($entry['aliases'] ?? [], fn ($id) => is_string($id) && preg_match('/^CVE-\d{4}-\d{4,}$/', $id))),
        ], $entries)]),
        'cve.now/api/v1/entries?*' => Http::response(['items' => $entries, 'missing' => []]),
    ];
}
