<?php

namespace App\Services;

use GuzzleHttp\Handler\StreamHandler;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use RuntimeException;

class CweService
{
    public function enrich(array $report): array
    {
        $deadline = microtime(true) + 20;
        $failed = false;
        try {
            foreach (['findings', 'reviewed_findings'] as $kind) {
                foreach ($report[$kind] ?? [] as $index => $finding) {
                    try {
                        $cves = array_values(array_unique(array_filter([$finding['id'], ...($finding['cve_ids'] ?? []), $finding['enclave']['id'] ?? null], fn ($id) => is_string($id) && preg_match('/^CVE-\d{4}-\d{4,}$/', $id))));
                        if (! $cves) {
                            continue;
                        }
                        $ids = [];
                        foreach ($cves as $cve) {
                            $ids = [...$ids, ...$this->mapping($cve, $deadline)];
                        }
                        $ids = array_values(array_unique($ids));
                        sort($ids);
                        $report[$kind][$index]['cwes'] = array_map(fn ($id) => ['id' => 'CWE-'.$id, 'name' => null, 'url' => 'https://cwe.mitre.org/data/definitions/'.$id.'.html'], $ids);
                        foreach ($ids as $position => $id) {
                            $report[$kind][$index]['cwes'][$position]['name'] = $this->name($id, $deadline);
                        }
                    } catch (\Throwable) {
                        $failed = true;
                    }
                }
            }
        } catch (\Throwable) {
            $failed = true;
        }
        if ($failed) {
            $report['warnings'][] = 'Some CWE classifications could not be loaded. Vulnerability matches and alerts are unchanged.';
        }

        return $report;
    }

    private function mapping(string $id, float $deadline): array
    {
        return Cache::remember('cwe:mapping:v1:'.$id, 86400, function () use ($id, $deadline) {
            preg_match('/^CVE-(\d{4})-(\d{4,})$/', $id, $parts);
            $record = Cache::get('cve-now:primary:'.$id) ?? $this->request('https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/'.$parts[1].'/'.substr($parts[2], 0, -3).'xxx/'.$id.'.json', $deadline);
            if (($record['cveMetadata']['cveId'] ?? null) !== $id || ($record['cveMetadata']['state'] ?? null) !== 'PUBLISHED') {
                throw new RuntimeException('CVE record could not be verified for CWE mapping.');
            }
            $ids = [];
            foreach ([$record['containers']['cna'] ?? [], ...($record['containers']['adp'] ?? [])] as $container) {
                foreach ($container['problemTypes'] ?? [] as $problem) {
                    foreach ($problem['descriptions'] ?? [] as $description) {
                        $cwe = $description['cweId'] ?? '';
                        if (is_string($cwe) && preg_match('/^CWE-([1-9]\d{0,5})$/', $cwe, $match)) {
                            $ids[] = $match[1];
                        }
                    }
                }
            }

            return array_values(array_unique($ids));
        });
    }

    private function name(string $id, float $deadline): string
    {
        return Cache::remember('cwe:name:v1:'.$id, 604800, function () use ($id, $deadline) {
            $data = $this->request('https://cwe-api.mitre.org/api/v1/cwe/weakness/'.$id, $deadline);
            foreach ($data['Weaknesses'] ?? [] as $weakness) {
                if ((string) ($weakness['ID'] ?? '') === $id && is_string($weakness['Name'] ?? null) && trim($weakness['Name']) !== '') {
                    return mb_substr($weakness['Name'], 0, 300);
                }
            }
            throw new RuntimeException('CWE API returned an incomplete weakness.');
        });
    }

    private function request(string $url, float $deadline): array
    {
        $remaining = $deadline - microtime(true);
        if ($remaining <= 0) {
            throw new RuntimeException('CWE enrichment time budget exceeded.');
        }
        $request = Http::acceptJson()->connectTimeout(min(3, $remaining))->timeout(min(5, $remaining))->withOptions(['allow_redirects' => false, 'verify' => true]);
        if (str_starts_with($url, 'https://cwe-api.mitre.org/')) {
            // MITRE's TLS close triggers cURL error 56; streams retain certificate and hostname verification.
            $request->setHandler(new StreamHandler);
        }
        $response = $request->get($url);
        $response->throw();
        $data = $response->json();
        if (! $response->successful() || ! is_array($data)) {
            throw new RuntimeException('CWE enrichment returned invalid data.');
        }

        return $data;
    }
}
