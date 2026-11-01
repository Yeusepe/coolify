<?php

namespace App\Services;

use App\Models\GithubApp;
use App\Models\Server;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

class SourceScanService
{
    public function report(Server $server): array
    {
        $path = 'security/source-scans/'.$server->uuid.'.json';

        return Storage::disk('local')->exists($path) ? json_decode(Storage::disk('local')->get($path), true, flags: JSON_THROW_ON_ERROR) : [];
    }

    public function saveReport(Server $server, array $report): void
    {
        Storage::disk('local')->put('security/source-scans/'.$server->uuid.'.json', json_encode($report, JSON_THROW_ON_ERROR), 'private');
    }

    public function repository(string $value): ?string
    {
        $value = preg_replace('~^(?:git@github\.com:|https://github\.com/)~i', '', trim($value));
        $value = preg_replace('~\.git$~', '', $value);
        if (! preg_match('~^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$~D', $value) || count(array_intersect(explode('/', $value), ['.', '..']))) {
            return null;
        }

        return $value;
    }

    public function targets(Server $server): array
    {
        $targets = [];
        $unsupported = [];
        foreach ($server->applications()->load('environment.project')->filter(fn ($application) => $application->environment?->project?->team_id === $server->team_id) as $application) {
            $repository = $this->repository($application->git_repository ?? '');
            if (! $repository || $application->build_pack === 'dockerimage') {
                $unsupported[] = $application->name;

                continue;
            }
            $deployed = $application->get_last_successful_deployment()?->commit;
            $ref = preg_match('/^[0-9a-f]{40}$/D', $deployed ?? '') ? $deployed : ($application->git_commit_sha !== 'HEAD' && $application->git_commit_sha ? $application->git_commit_sha : $application->git_branch);
            $id = hash('sha256', strtolower($repository).'|'.$ref);
            if (isset($targets[$id])) {
                $targets[$id]['applications'][] = $application->name;

                continue;
            }
            $target = ['id' => $id, 'repository' => $repository, 'ref' => $ref, 'ref_kind' => preg_match('/^[0-9a-f]{40}$/D', $deployed ?? '') ? 'Deployed commit' : 'Configured reference', 'applications' => [$application->name]];
            try {
                if ($application->private_key_id) {
                    $key = $application->private_key;
                    if (! $key || $key->team_id !== $server->team_id) {
                        throw new \RuntimeException;
                    }
                    $target['private_key'] = $key->private_key;
                } elseif ($application->source instanceof GithubApp && ! $application->source->is_public) {
                    $source = $application->source;
                    if ($source->team_id !== $server->team_id || rtrim($source->html_url, '/') !== 'https://github.com' || rtrim($source->api_url, '/') !== 'https://api.github.com') {
                        throw new \RuntimeException;
                    }
                    $target['token'] = generateGithubInstallationToken($source);
                } elseif ($application->source && ! ($application->source instanceof GithubApp)) {
                    throw new \RuntimeException;
                }
            } catch (\Throwable) {
                $target['unavailable'] = true;
            }
            $targets[$id] = $target;
        }

        $previous = collect($this->report($server)['repositories'] ?? [])->keyBy('id');
        $targets = collect($targets)->sortBy(fn ($target) => $previous->get($target['id'])['attempted_at'] ?? $previous->get($target['id'])['checked_at'] ?? '')->values()->all();

        return ['targets' => $targets, 'unsupported' => $unsupported];
    }

    public function collect(Server $server): array
    {
        if ($this->architecture($server) !== 'x86_64') {
            return [...$this->report($server), 'unsupported_host' => true, 'error' => 'Source scanning currently requires a Linux x86-64 server. Automatic scans are paused for this host. Scan manually after changing the host architecture.', 'attempted_at' => now()->toIso8601String()];
        }
        $inventory = $this->targets($server);
        $targets = array_values(array_filter($inventory['targets'], fn ($target) => ! isset($target['unavailable'])));
        $results = [];
        if ($targets) {
            $directory = '/tmp/racconify-source-request-'.Str::random(24);
            instant_remote_process(['install -d -m 700 '.escapeshellarg($directory)], $server);
            try {
                instant_remote_write_file($server, $directory.'/runner.py', file_get_contents(resource_path('scripts/source-scan.py')));
                instant_remote_write_file($server, $directory.'/request.json', json_encode(['image' => config('services.source_scanning.image'), 'targets' => $targets], JSON_THROW_ON_ERROR));
                instant_remote_process(['chmod 600 '.escapeshellarg($directory.'/request.json')], $server);
                $output = instant_remote_process(['python3 '.escapeshellarg($directory.'/runner.py').' '.escapeshellarg($directory.'/request.json')], $server, timeout: 2400);
                $data = json_decode($output ?? '', true, flags: JSON_THROW_ON_ERROR);
                if (! isset($data['repositories'])) {
                    throw new \RuntimeException('Source scan could not complete.');
                }
                $results = array_column($data['repositories'], null, 'id');
            } finally {
                instant_remote_process(['rm -rf -- '.escapeshellarg($directory)], $server, throwError: false);
            }
        }

        return $this->merge($this->report($server), $inventory, $results);
    }

    public function architecture(Server $server): string
    {
        return trim(instant_remote_process(['uname -m'], $server) ?? '');
    }

    public function merge(array $previous, array $inventory, array $results): array
    {
        $repositories = [];
        foreach ($inventory['targets'] as $target) {
            unset($target['token'], $target['private_key'], $target['unavailable']);
            $result = $results[$target['id']] ?? ['status' => 'failed', 'error' => 'Repository credentials or source access are unavailable.'];
            if (in_array($result['status'] ?? 'failed', ['failed', 'deferred'], true)) {
                $old = collect($previous['repositories'] ?? [])->firstWhere('id', $target['id']) ?? collect($previous['repositories'] ?? [])->firstWhere('repository', $target['repository']) ?? [];
                $deferred = ($result['status'] ?? '') === 'deferred';
                $repositories[] = [...$old, ...$target, 'status' => $deferred ? 'deferred' : 'failed', 'error' => $deferred ? 'Scan time budget reached. This repository will be prioritized on the next run. Previous findings, if any, remain below.' : 'Repository fetch or isolated scan failed. Previous findings, if any, remain below.', 'attempted_at' => $deferred ? ($old['attempted_at'] ?? $old['checked_at'] ?? null) : now()->toIso8601String()];
            } else {
                $repositories[] = [...$target, ...$result, 'checked_at' => now()->toIso8601String(), 'attempted_at' => now()->toIso8601String()];
            }
        }

        return ['attempted_at' => now()->toIso8601String(), 'repositories' => $repositories, 'unsupported' => $inventory['unsupported']];
    }
}
