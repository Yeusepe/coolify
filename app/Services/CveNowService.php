<?php

namespace App\Services;

use App\Models\Server;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Storage;
use InvalidArgumentException;
use RuntimeException;

class CveNowService
{
    public function collect(Server $server): array
    {
        $command = $this->inventoryCommand();
        $raw = instant_remote_process([$command], $server, timeout: 600, disableMultiplexing: true);
        if (! is_string($raw) || strlen($raw) > 16000000) {
            throw new RuntimeException('The software inventory could not be read.');
        }
        $data = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        if (! isset($data['packages'], $data['runtimes'], $data['containers'])) {
            throw new RuntimeException('The software inventory is incomplete.');
        }

        return $data;
    }

    public function inventoryCommand(): string
    {
        $script = file_get_contents(resource_path('scripts/cve-inventory.py'));

        return 'python3 -c '.escapeshellarg('import base64; exec(base64.b64decode("'.base64_encode($script).'"))');
    }

    public function check(array $inventory): array
    {
        $packages = [];
        foreach ($inventory['packages'] ?? [] as $package) {
            try {
                $parsed = $this->parsePackages($package['ecosystem'].':'.$package['name'].'@'.$package['version'])[0];
            } catch (InvalidArgumentException) {
                $inventory['warnings'][] = 'An installed package has no supported exact release version and was skipped.';

                continue;
            }
            $key = $parsed['ecosystem'].':'.$parsed['name'].'@'.$parsed['version'];
            $packages[$key]['package'] = $parsed;
            $packages[$key]['contexts'][] = mb_substr($package['container'] ?? 'Host', 0, 160);
        }
        ksort($packages);
        $findings = [];
        foreach (array_chunk(array_keys($packages), 25) as $batch) {
            $data = $this->request('/stack', ['p' => implode(',', $batch), 'format' => 'json']);
            if (! isset($data['entries'], $data['packages']) || ! is_array($data['entries']) || $data['packages'] !== count($batch)) {
                throw new RuntimeException('CVE.now returned an incomplete package response.');
            }
            foreach ($data['entries'] as $entry) {
                $matched = $entry['matched'] ?? [];
                $matchedPackage = $this->parsePackages(strtolower($matched['ecosystem'] ?? '').':'.($matched['name'] ?? '').'@'.($matched['version'] ?? ''))[0] ?? [];
                $key = ($matchedPackage['ecosystem'] ?? '').':'.($matchedPackage['name'] ?? '').'@'.($matchedPackage['version'] ?? '');
                if (! in_array($key, $batch, true)) {
                    throw new RuntimeException('CVE.now returned a match outside the submitted inventory.');
                }
                $finding = $this->finding($entry, $packages[$key]['package'], array_values(array_unique($packages[$key]['contexts'])), 'Package version match');
                $findings[$finding['id'].'|'.$key] = $finding;
            }
        }

        $technologyNames = ['php' => ['php'], 'node' => ['node', 'node.js', 'nodejs'], 'docker' => ['docker', 'docker engine', 'docker_engine', 'docker-ce', 'moby']];
        foreach ($technologyNames as $technology => $products) {
            $runtimes = array_values(array_filter($inventory['runtimes'] ?? [], fn ($r) => $r['name'] === $technology));
            if (! $runtimes) {
                continue;
            }
            $feed = $this->request('/feed', ['tech' => $technology, 'filter' => 'critical', 'format' => 'json']);
            if (! isset($feed['items']) || ! is_array($feed['items'])) {
                throw new RuntimeException('CVE.now returned an incomplete technology feed.');
            }
            $ids = [];
            foreach ($feed['items'] as $item) {
                $id = explode('#', $item['id'] ?? '')[0];
                if (preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{2,100}$/', $id)) {
                    $ids[$id] = true;
                }
                if (count($ids) >= 25) {
                    break;
                }
            }
            foreach (array_keys($ids) as $id) {
                $entry = $this->request('/api/v1/entries/'.$id);
                foreach ($entry['affected'] ?? [] as $affected) {
                    if (! in_array(strtolower($affected['product'] ?? $affected['package'] ?? ''), $products, true)) {
                        continue;
                    }
                    foreach ($runtimes as $runtime) {
                        $match = $this->inRanges($runtime['version'], $affected['ranges'] ?? []);
                        if ($match === false) {
                            continue;
                        }
                        $package = ['ecosystem' => 'runtime', 'name' => $technology, 'version' => $runtime['version']];
                        $key = $id.'|runtime:'.$technology.'@'.$runtime['version'];
                        $contexts = array_unique([...($findings[$key]['contexts'] ?? []), $runtime['container']]);
                        $runtimeEntry = [...$entry, 'affected' => [$affected]];
                        $findings[$key] = $this->finding($runtimeEntry, $package, array_values($contexts), $match === true ? 'Runtime version range match' : 'Technology advisory. Check vendor applicability');
                    }
                }
            }
        }
        $findings = array_values($findings);
        usort($findings, fn ($a, $b) => $b['score'] <=> $a['score']);

        return ['checked_at' => now()->toIso8601String(), 'packages_checked' => count($packages), 'containers' => $inventory['containers'] ?? [], 'runtimes' => $inventory['runtimes'] ?? [], 'warnings' => $inventory['warnings'] ?? [], 'findings' => $findings, 'error' => null];
    }

    private function request(string $path, array $query = []): array
    {
        $key = 'cve-now:http:'.hash('sha256', $path.json_encode($query));

        return Cache::remember($key, 3600, function () use ($path, $query) {
            $url = 'https://cve.now'.$path;
            for ($redirects = 0; $redirects < 4; $redirects++) {
                $response = Http::acceptJson()->connectTimeout(5)->timeout(25)->withOptions(['allow_redirects' => false])->get($url, $query);
                if ($response->redirect()) {
                    $next = $response->header('Location');
                    if (str_starts_with($next, '/') && ! str_starts_with($next, '//')) {
                        $next = 'https://cve.now'.$next;
                    }
                    $host = parse_url($next, PHP_URL_HOST);
                    $safeHost = $host === 'cve.now' || ($host === 'f9gkulwameaj0boi.public.blob.vercel-storage.com' && str_starts_with(parse_url($next, PHP_URL_PATH) ?? '', '/public/entries/'));
                    if (parse_url($next, PHP_URL_SCHEME) !== 'https' || ! $safeHost || parse_url($next, PHP_URL_USER) || parse_url($next, PHP_URL_PORT)) {
                        throw new RuntimeException('CVE.now returned an unsafe redirect.');
                    }
                    $url = $next;
                    $query = [];

                    continue;
                }
                $response->throw();
                $data = $response->json();
                if (! is_array($data)) {
                    throw new RuntimeException('CVE.now returned invalid JSON.');
                }

                return $data;
            }
            throw new RuntimeException('CVE.now redirected too many times.');
        });
    }

    public function inRanges(string $version, array $ranges): ?bool
    {
        if (! preg_match('/^v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?$/', $version) || ! $ranges) {
            return null;
        }
        $version = ltrim($version, 'v');
        foreach ($ranges as $range) {
            if (! array_intersect(['introduced', 'fixed', 'limit', 'lastAffected', 'last_affected'], array_keys($range))) {
                return null;
            }
            $start = ltrim($range['introduced'] ?? '0', 'v');
            $fixed = $range['fixed'] ?? $range['limit'] ?? null;
            $last = $range['lastAffected'] ?? $range['last_affected'] ?? null;
            foreach (array_filter([$start === '0' ? null : $start, $fixed, $last]) as $boundary) {
                if (! preg_match('/^v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?$/', $boundary)) {
                    return null;
                }
            }
            if (($start === '0' || version_compare($version, $start, '>=')) && (! $fixed || version_compare($version, ltrim($fixed, 'v'), '<')) && (! $last || version_compare($version, ltrim($last, 'v'), '<='))) {
                return true;
            }
        }

        return false;
    }

    private function finding(array $entry, array $package, array $contexts, string $kind): array
    {
        $id = $entry['id'] ?? '';
        if (! preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{2,100}$/', $id)) {
            throw new RuntimeException('CVE.now returned an invalid advisory identifier.');
        }
        $fixed = [];
        foreach ($entry['affected'] ?? [] as $affected) {
            if ($package['ecosystem'] !== 'runtime' && $this->packageName($package['ecosystem'], $affected['package'] ?? '') !== $package['name']) {
                continue;
            }
            foreach ($affected['ranges'] ?? [] as $range) {
                if (isset($range['fixed'])) {
                    $fixed[] = mb_substr($range['fixed'], 0, 80);
                }
            }
        }
        $fixed = array_values(array_unique($fixed));
        sort($fixed);

        return ['id' => $id, 'title' => mb_substr($entry['title'] ?? $entry['originalDescription'] ?? $id, 0, 500), 'score' => (float) ($entry['severity']['cvss'] ?? 0), 'known_exploited' => (bool) ($entry['exploitation']['kev'] ?? false), 'package' => $package['name'], 'version' => $package['version'], 'ecosystem' => $package['ecosystem'], 'contexts' => $contexts, 'kind' => $kind, 'fixed' => $fixed, 'url' => 'https://cve.now/'.rawurlencode($id)];
    }

    public function parsePackages(string $text): array
    {
        $packages = [];
        $lines = preg_split('/\R/', trim($text));
        if (count($lines) > 200) {
            throw new InvalidArgumentException('Use at most 200 additional packages.');
        }
        foreach ($lines as $line) {
            if (trim($line) === '') {
                continue;
            }
            if (! preg_match('/^(npm|packagist|pypi|nuget|go|crates\.io|rubygems|maven):([A-Za-z0-9@][A-Za-z0-9._@\/+:-]{0,180})@(v?\d[A-Za-z0-9.+_-]{0,79})$/', trim($line), $matches)) {
                throw new InvalidArgumentException('Use ecosystem:package@exact-version, for example npm:next@16.4.2.');
            }
            $packages[] = ['ecosystem' => $matches[1], 'name' => $this->packageName($matches[1], $matches[2]), 'version' => ltrim($matches[3], 'v'), 'container' => 'Additional technology'];
        }

        return $packages;
    }

    private function packageName(string $ecosystem, string $name): string
    {
        if ($ecosystem === 'pypi') {
            return preg_replace('/[-_.]+/', '-', strtolower($name));
        }

        return in_array($ecosystem, ['npm', 'packagist', 'nuget'], true) ? strtolower($name) : $name;
    }

    public function report(Server $server): array
    {
        return $this->readFile($server, 'report');
    }

    public function settings(Server $server): array
    {
        return $this->readFile($server, 'settings');
    }

    private function readFile(Server $server, string $kind): array
    {
        $path = $this->path($server, $kind);

        return Storage::disk('local')->exists($path) ? json_decode(Storage::disk('local')->get($path), true, flags: JSON_THROW_ON_ERROR) : [];
    }

    public function saveReport(Server $server, array $data): void
    {
        Storage::disk('local')->put($this->path($server, 'report'), json_encode($data, JSON_THROW_ON_ERROR));
    }

    public function savePackages(Server $server, string $text): void
    {
        $this->parsePackages($text);
        Storage::disk('local')->put($this->path($server, 'settings'), json_encode(['packages' => $text], JSON_THROW_ON_ERROR));
    }

    public function recordFailure(Server $server): void
    {
        $this->saveReport($server, [...$this->report($server), 'error' => 'The vulnerability check failed. Previous results are retained.', 'failed_at' => now()->toIso8601String()]);
    }

    private function path(Server $server, string $kind): string
    {
        if (! preg_match('/^[A-Za-z0-9_-]+$/', $server->uuid)) {
            throw new InvalidArgumentException('Invalid server identifier.');
        }

        return 'security/cve-now/'.$server->uuid.'-'.$kind.'.json';
    }
}
