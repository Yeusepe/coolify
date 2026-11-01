<?php

namespace App\Livewire\Server\Security;

use App\Jobs\ServerSourceScanJob;
use App\Models\Server;
use App\Services\SourceScanService;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Support\Facades\Cache;
use Illuminate\View\View;
use Livewire\Attributes\Locked;
use Livewire\Component;

class SourceScanning extends Component
{
    use AuthorizesRequests;

    #[Locked]
    public Server $server;

    public int $page = 1;

    public function mount(string $server_uuid): void
    {
        $this->server = Server::ownedByCurrentTeam()->whereUuid($server_uuid)->firstOrFail();
        $this->authorize('viewSecurity', $this->server);
    }

    public function scan(): void
    {
        $this->authorize('update', $this->server);
        if (config('services.source_scanning.enabled') && Cache::add('source-scan:pending:'.$this->server->uuid, true, 2800)) {
            ServerSourceScanJob::dispatch($this->server);
        }
    }

    public function render(): View
    {
        $this->authorize('viewSecurity', $this->server);
        $report = app(SourceScanService::class)->report($this->server);
        $findings = [];
        foreach ($report['repositories'] ?? [] as $repository) {
            foreach ($repository['findings'] ?? [] as $finding) {
                $findings[] = [...$finding, 'repository' => $repository['repository'], 'commit' => $repository['commit'], 'stale' => $repository['status'] === 'failed'];
            }
        }
        $pages = max(1, (int) ceil(count($findings) / 25));
        $page = max(1, min($pages, $this->page));

        return view('livewire.server.security.source-scanning', ['report' => $report, 'findings' => array_slice($findings, ($page - 1) * 25, 25), 'findingCount' => count($findings), 'page' => $page, 'pages' => $pages, 'pending' => Cache::has('source-scan:pending:'.$this->server->uuid), 'enabled' => (bool) config('services.source_scanning.enabled')]);
    }
}
