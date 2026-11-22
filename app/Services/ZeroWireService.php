<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use RuntimeException;

class ZeroWireService
{
    public function briefings(array $inventory, array $findings): array
    {
        $feed = $this->feed();
        $briefings = [];
        $runtimeTags = ['php' => ['php'], 'node' => ['node', 'node.js', 'nodejs'], 'docker' => ['docker', 'moby'], 'postgresql' => ['postgresql', 'postgres'], 'redis' => ['redis'], 'nginx' => ['nginx'], 'openssl' => ['openssl'], 'go' => ['go', 'golang'], 'dotnet' => ['asp.net', '.net'], 'mongodb' => ['mongodb']];
        $packageTags = ['next' => ['next.js', 'nextjs'], 'react' => ['react', 'react server components'], 'react-dom' => ['react', 'react server components'], 'react-server-dom-webpack' => ['react server components'], 'react-server-dom-turbopack' => ['react server components']];
        foreach ($feed['items'] as $item) {
            $extension = $item['_zero_wire'];
            $tags = array_map('strtolower', $item['tags'] ?? []);
            $contexts = [];
            $matched = [];
            foreach ($findings as $finding) {
                $ids = array_intersect($extension['cves'], [$finding['id'], ...($finding['cve_ids'] ?? [])]);
                if ($ids) {
                    $matched = [...$matched, ...$ids];
                    $contexts = [...$contexts, ...$finding['contexts']];
                }
            }
            foreach ($inventory['runtimes'] ?? [] as $runtime) {
                if (! in_array('cms', $tags, true) && array_intersect($tags, $runtimeTags[$runtime['name']] ?? [$runtime['name']])) {
                    $contexts[] = $runtime['container'];
                }
            }
            foreach ($inventory['packages'] ?? [] as $package) {
                if ($package['ecosystem'] === 'npm' && array_intersect($tags, $packageTags[$package['name']] ?? [])) {
                    $contexts[] = $package['container'] ?? 'Host';
                }
            }
            if (! $contexts) {
                continue;
            }
            $briefings[] = ['url' => $item['url'], 'title' => mb_substr($item['title'], 0, 500), 'summary' => mb_substr($extension['summary'], 0, 2000),
                'reviewed_at' => $extension['last_reviewed'], 'cves' => $extension['cves'],
                'matched_cves' => array_values(array_unique($matched)), 'contexts' => array_values(array_unique($contexts)),
                'steps' => array_map(fn ($step) => mb_substr($step['text'], 0, 2000), array_slice($extension['recommended_action_steps'], 0, 10)),
            ];
        }

        return ['checked_at' => $feed['checked_at'], 'briefings' => $briefings];
    }

    private function feed(): array
    {
        return Cache::remember('cloudflare:zero-wire:v1', 3600, function () {
            $response = Http::acceptJson()->connectTimeout(5)->timeout(20)->withOptions(['allow_redirects' => false])->get('https://radar.cloudflare.com/zero-wire/feed?format=json');
            $response->throw();
            $feed = $response->json();
            if ($response->redirect() || strlen($response->body()) > 4000000 || ! is_array($feed) || ! in_array($feed['version'] ?? null, ['https://jsonfeed.org/version/1', 'https://jsonfeed.org/version/1.1'], true) || ! is_array($feed['items'] ?? null) || ! array_is_list($feed['items']) || count($feed['items']) > 200) {
                throw new RuntimeException('Cloudflare returned an incomplete Zero Wire feed.');
            }
            $items = [];
            foreach ($feed['items'] as $item) {
                $extension = $item['_zero_wire'] ?? [];
                if (! is_string($item['url'] ?? null) || ! preg_match('~^https://radar\.cloudflare\.com/zero-wire/[a-z0-9][a-z0-9-]*/?$~D', $item['url']) || ! is_string($item['title'] ?? null) || ! is_string($extension['summary'] ?? null) || ! is_string($extension['last_reviewed'] ?? null) || ! preg_match('/^\d{4}-\d{2}-\d{2}$/D', $extension['last_reviewed']) || ! is_array($extension['cves'] ?? null) || ! array_is_list($extension['cves']) || count($extension['cves']) > 100 || ! is_array($extension['recommended_action_steps'] ?? null) || ! array_is_list($extension['recommended_action_steps']) || ! is_array($item['tags'] ?? []) || ! array_is_list($item['tags'] ?? [])) {
                    throw new RuntimeException('Cloudflare returned an invalid Zero Wire briefing.');
                }
                foreach ($extension['cves'] as $id) {
                    if (! is_string($id) || ! preg_match('/^CVE-\d{4}-\d{4,}$/D', $id)) {
                        throw new RuntimeException('Cloudflare returned an invalid CVE identifier.');
                    }
                }
                foreach ($item['tags'] ?? [] as $tag) {
                    if (! is_string($tag)) {
                        throw new RuntimeException('Cloudflare returned an invalid technology tag.');
                    }
                }
                foreach ($extension['recommended_action_steps'] as $step) {
                    if (! is_string($step['text'] ?? null)) {
                        throw new RuntimeException('Cloudflare returned an invalid recommended step.');
                    }
                }
                $items[] = ['url' => $item['url'], 'title' => $item['title'], 'tags' => $item['tags'] ?? [], '_zero_wire' => array_intersect_key($extension, array_flip(['summary', 'last_reviewed', 'cves', 'recommended_action_steps']))];
            }

            return ['checked_at' => now()->toIso8601String(), 'items' => $items];
        });
    }
}
