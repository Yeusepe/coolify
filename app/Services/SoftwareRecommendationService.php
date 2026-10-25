<?php

namespace App\Services;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use UnexpectedValueException;

class SoftwareRecommendationService
{
    private const PRODUCTS = [
        'node' => ['Node.js', 'nodejs/node', 1],
        'bun' => ['Bun', 'oven-sh/bun', 1],
        'php' => ['PHP', 'php', 2],
        'docker' => ['Docker Engine', 'moby/moby', 1],
        'dotnet' => ['ASP.NET Core', 'dotnet', 1],
        'postgresql' => ['PostgreSQL', 'postgresql', 1],
        'redis' => ['Redis', 'redis/redis', 2],
        'mongodb' => ['MongoDB', 'mongodb', 2],
        'nginx' => ['Nginx', 'nginx/nginx', 2],
        'openssl' => ['OpenSSL', 'openssl/openssl', 2],
        'traefik' => ['Traefik', 'traefik/traefik', 1],
        'caddy' => ['Caddy', 'caddyserver/caddy', 1],
        'deno' => ['Deno', 'denoland/deno', 1],
        'minio' => ['MinIO', 'minio/minio', 0],
        'mediamtx' => ['MediaMTX', 'bluenviron/mediamtx', 1],
        'postgrest' => ['PostgREST', 'PostgREST/postgrest', 1],
        'kong' => ['Kong', 'Kong/kong', 2],
        'go' => ['Go runtime', 'go', 2],
        'next' => ['Next.js', 'npm:next', 1],
        'react' => ['React', 'npm:react', 1],
        'fastify' => ['Fastify', 'npm:fastify', 1],
        'express' => ['Express', 'npm:express', 1],
        'hono' => ['Hono', 'npm:hono', 1],
        'elysia' => ['Elysia', 'npm:elysia', 1],
        'vue' => ['Vue', 'npm:vue', 1],
        'svelte' => ['Svelte', 'npm:svelte', 1],
        'nuxt' => ['Nuxt', 'npm:nuxt', 1],
        'laravel/framework' => ['Laravel', 'laravel/framework', 1],
    ];

    public function recommend(array $inventory, array $findings): array
    {
        $detected = [];
        foreach ($inventory['runtimes'] ?? [] as $runtime) {
            $key = $runtime['name'].'@'.$runtime['version'].'#'.($runtime['revision'] ?? '');
            $detected[$key]['record'] = $runtime;
            $detected[$key]['contexts'][] = $runtime['container'];
        }
        foreach ($inventory['packages'] ?? [] as $package) {
            $name = $package['name'];
            if (! in_array($name, ['next', 'react', 'fastify', 'express', 'hono', 'elysia', 'vue', 'svelte', 'nuxt', 'laravel/framework'], true) || ! in_array($package['ecosystem'], ['npm', 'packagist'], true)) {
                continue;
            }
            $key = $name.'@'.$package['version'];
            $detected[$key]['record'] = [...$package, 'name' => $name];
            $detected[$key]['contexts'][] = $package['container'];
        }
        $software = [];
        foreach ($detected as $item) {
            $runtime = $item['record'];
            $name = $runtime['name'];
            $product = self::PRODUCTS[$name] ?? [ucfirst($name), null, 1];
            $row = ['technology' => $name, 'name' => $product[0], 'version' => $runtime['version'], 'revision' => $runtime['revision'] ?? null, 'contexts' => array_values(array_unique($item['contexts'])), 'target' => null, 'status' => 'Release lookup unavailable', 'url' => null, 'recommendation' => 'No supported vendor release lookup. Verify the running image with its vendor.'];
            if ($product[1]) {
                try {
                    [$versions, $url] = $this->releases($product[1], $runtime['version']);
                    $row['url'] = $url;
                    if (! preg_match('/^(?:v?\d+\.\d+(?:\.\d+){0,2}(?:[-+][A-Za-z0-9._-]+)?|RELEASE\.\d{4}-\d\d-\d\dT\d\d-\d\d-\d\dZ)$/', preg_replace('/\+.*/', '', $runtime['version']))) {
                        $row['status'] = 'Build identity requires review';
                        $row['recommendation'] = 'This binary does not report a comparable release version. Verify its pinned build provenance and security patches before replacing it. Do not assume a vendor image is a safe replacement.';
                        $software[] = $row;

                        continue;
                    }
                    $sameLine = array_values(array_filter($versions, fn ($version) => $this->line($version, $product[2]) === $this->line($runtime['version'], $product[2])));
                    $row['target'] = $sameLine[0] ?? $versions[0];
                    $newer = version_compare($this->comparable($row['target']), $this->comparable($runtime['version']), '>');
                    $row['status'] = $newer ? ($sameLine ? 'Update available' : 'Migration review required') : 'No newer release found';
                    $row['recommendation'] = $newer ? $this->updateAdvice($name, ! $sameLine) : 'No newer stable release was found in the queried vendor data for this release line. This is not a security assessment.';
                    if (! $newer && preg_match('/(?:alpha|beta|rc|canary|dev)/i', $runtime['version'])) {
                        $row['status'] = 'Preview build requires review';
                        $row['recommendation'] = 'Keep the pinned security build until a stable release containing its fixes is verified. Do not downgrade automatically.';
                    }
                    if ($name === 'bun' && ! $newer && $row['revision'] && $row['target'] === $runtime['version']) {
                        $referenceUrl = 'https://api.github.com/repos/oven-sh/bun/git/ref/tags/bun-v'.$row['target'];
                        $reference = Cache::remember('software-build:'.hash('sha256', $referenceUrl), 3600, fn () => Http::acceptJson()->withUserAgent('Racconify-Software-Monitor')->connectTimeout(5)->timeout(20)->withOptions(['allow_redirects' => false])->get($referenceUrl)->throw()->json('object'));
                        if (! is_array($reference) || ($reference['type'] ?? '') !== 'commit' || ! preg_match('/^[a-f0-9]{40}$/', $reference['sha'] ?? '')) {
                            throw new UnexpectedValueException('The Bun release build could not be verified.');
                        }
                        if (! str_starts_with($reference['sha'], $row['revision'])) {
                            $row['status'] = 'Build identity requires review';
                            $row['recommendation'] = 'The version label matches, but the installed Bun build differs from the tagged stable release. Review the pinned security patches and test the stable build before replacing it.';
                        }
                    }
                } catch (ConnectionException|RequestException|UnexpectedValueException $exception) {
                    $row['status'] = 'Release lookup failed';
                    $row['recommendation'] = 'Vendor release data could not be verified. Existing software must not be treated as current or safe from this result.';
                }
            }
            $software[] = $row;
        }
        usort($software, fn ($a, $b) => [$a['name'], $a['version']] <=> [$b['name'], $b['version']]);

        $resources = $inventory['containers'] ?? [];
        foreach ($resources as &$resource) {
            $label = $resource['resource'] ?? $resource['name'];
            $resource['software'] = array_values(array_map(fn ($s) => $s['name'].' '.$s['version'], array_filter($software, fn ($s) => in_array($label, $s['contexts'], true))));
        }
        unset($resource);

        return ['software' => $software, 'package_updates' => $this->packageUpdates($findings), 'resources' => $resources, 'host' => $inventory['host'] ?? []];
    }

    private function releases(string $source, string $installed): array
    {
        $line = $this->line($installed, 2);
        if (in_array($source, ['php', 'dotnet'], true) && ! preg_match('/^\d+\.\d+$/', $line)) {
            throw new UnexpectedValueException('Unsupported release version.');
        }
        $url = match ($source) {
            'php' => 'https://www.php.net/releases/index.php?json&version='.$line,
            'dotnet' => 'https://builds.dotnet.microsoft.com/dotnet/release-metadata/'.$this->line($installed, 1).'.0/releases.json',
            'postgresql' => 'https://www.postgresql.org/versions.rss',
            'mongodb' => 'https://downloads.mongodb.org/current.json',
            'go' => 'https://go.dev/dl/?mode=json',
            default => str_starts_with($source, 'npm:') ? 'https://registry.npmjs.org/'.rawurlencode(substr($source, 4)).'/latest' : 'https://api.github.com/repos/'.$source.'/releases?per_page=30',
        };
        $versions = Cache::remember('software-releases:'.hash('sha256', $url), 3600, function () use ($url, $source) {
            $response = Http::acceptJson()->withUserAgent('Racconify-Software-Monitor')->connectTimeout(5)->timeout(20)->withOptions(['allow_redirects' => false])->get($url)->throw();
            $data = $response->json();
            if ($source === 'postgresql') {
                preg_match_all('/<title>\s*(\d+\.\d+(?:\.\d+)?)\s*<\/title>/', $response->body(), $matches);
                $versions = $matches[1];
            } elseif ($source === 'php' || str_starts_with($source, 'npm:')) {
                $versions = [$data['version'] ?? ''];
            } elseif ($source === 'dotnet') {
                $versions = [$data['latest-runtime'] ?? ''];
            } elseif ($source === 'mongodb') {
                $versions = array_column($data['versions'] ?? [], 'version');
            } elseif ($source === 'go') {
                $versions = array_map(fn ($r) => preg_replace('/^go/', '', $r['version'] ?? ''), array_filter(is_array($data) ? $data : [], fn ($r) => is_array($r) && ($r['stable'] ?? false)));
            } else {
                $versions = [];
                foreach (is_array($data) ? $data : [] as $release) {
                    if (! is_array($release) || ($release['prerelease'] ?? false) || ($release['draft'] ?? false)) {
                        continue;
                    }
                    $tag = $release['tag_name'] ?? '';
                    if (preg_match('/^(?:v|bun-v|docker-v|release-|openssl-)?(\d+\.\d+(?:\.\d+){0,2})$/', $tag, $match)) {
                        $versions[] = $match[1];
                    } elseif ($source === 'minio/minio' && preg_match('/^RELEASE\.\d{4}-\d\d-\d\dT\d\d-\d\d-\d\dZ$/', $tag)) {
                        $versions[] = $tag;
                    }
                }
            }
            $versions = array_values(array_unique(array_filter($versions, fn ($v) => is_string($v) && preg_match('/^(?:\d+\.\d+(?:\.\d+){0,2}|RELEASE\.\d{4}-\d\d-\d\dT\d\d-\d\d-\d\dZ)$/', $v))));
            if (! $versions) {
                throw new UnexpectedValueException('Vendor returned no supported stable release versions.');
            }
            usort($versions, fn ($a, $b) => version_compare($this->comparable($b), $this->comparable($a)));

            return $versions;
        });
        $link = match ($source) {
            'php' => 'https://www.php.net/releases/',
            'dotnet' => 'https://dotnet.microsoft.com/en-us/download/dotnet/'.$this->line($installed, 1).'.0',
            'postgresql' => 'https://www.postgresql.org/support/versioning/',
            'mongodb' => 'https://www.mongodb.com/docs/manual/release-notes/',
            'go' => 'https://go.dev/doc/devel/release',
            default => str_starts_with($source, 'npm:') ? 'https://www.npmjs.com/package/'.rawurlencode(substr($source, 4)) : 'https://github.com/'.$source.'/releases',
        };

        return [$versions, $link];
    }

    private function comparable(string $version): string
    {
        return str_starts_with($version, 'RELEASE.') ? preg_replace('/[^0-9]+/', '.', substr($version, 8)) : preg_replace('/\+.*/', '', ltrim($version, 'v'));
    }

    private function line(string $version, int $parts): string
    {
        if ($parts === 0) {
            return '';
        }
        preg_match('/^(\d+(?:\.\d+)*)/', ltrim($version, 'v'), $match);

        return implode('.', array_slice(explode('.', $match[1] ?? ''), 0, $parts));
    }

    private function updateAdvice(string $name, bool $migration): string
    {
        $prefix = $migration ? 'No current-line release was found. Review the vendor migration and compatibility requirements. ' : '';
        if (in_array($name, ['postgresql', 'redis', 'mongodb', 'minio', 'kong'], true)) {
            return $prefix.'Back up persistent data and review the stack compatibility matrix before updating its image. Upgrade Supabase components together as a compatible stack.';
        }
        if ($name === 'docker') {
            return $prefix.'Apply the host package update through Server patching, then verify Docker and application health.';
        }
        if (in_array($name, ['traefik', 'caddy'], true)) {
            return $prefix.'Update the managed proxy after reviewing its configuration and compatibility.';
        }
        if (in_array($name, ['openssl', 'nginx'], true)) {
            return $prefix.'Update the image or distribution package. Confirm vendor backports before treating an older upstream version as vulnerable.';
        }

        return $prefix.'Update the application dependency or base image, test it, and redeploy the affected applications through racconify.';
    }

    public function packageUpdates(array $findings): array
    {
        $updates = [];
        foreach ($findings as $finding) {
            if ($finding['kind'] !== 'Package version match') {
                continue;
            }
            $key = $finding['ecosystem'].':'.$finding['package'].'@'.$finding['version'];
            $row = $updates[$key] ?? ['package' => $finding['package'], 'ecosystem' => $finding['ecosystem'], 'version' => $finding['version'], 'contexts' => [], 'advisories' => [], 'targets' => [], 'score' => 0];
            $row['contexts'] = array_values(array_unique([...$row['contexts'], ...$finding['contexts']]));
            $row['advisories'][] = ['id' => $finding['id'], 'url' => $finding['url']];
            $row['score'] = max($row['score'], $finding['score']);
            $valid = array_values(array_filter($finding['fixed'], fn ($v) => preg_match('/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/', $v) && version_compare($v, $finding['version'], '>')));
            $sameMajor = array_values(array_filter($valid, fn ($v) => $this->line($v, 1) === $this->line($finding['version'], 1)));
            $candidates = $sameMajor ?: $valid;
            usort($candidates, 'version_compare');
            $row['targets'][] = $candidates[0] ?? null;
            $updates[$key] = $row;
        }
        foreach ($updates as &$row) {
            $targets = array_values(array_filter($row['targets']));
            usort($targets, fn ($a, $b) => version_compare($b, $a));
            $row['target'] = $targets[0] ?? null;
            $row['status'] = count($targets) !== count($row['targets']) ? 'Vendor review required' : ($this->line($row['target'], 1) !== $this->line($row['version'], 1) ? 'Migration review required' : 'Review security update');
            $row['recommendation'] = 'Review the linked advisories and confirm applicability. Rebuild and redeploy the affected application image after testing.';
            unset($row['targets']);
        }
        unset($row);
        $updates = array_values($updates);
        usort($updates, fn ($a, $b) => $b['score'] <=> $a['score']);

        return $updates;
    }
}
