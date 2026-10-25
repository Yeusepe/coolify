<?php

namespace App\Livewire\Server\Security;

use App\Jobs\ServerVulnerabilityCheckJob;
use App\Models\Server;
use App\Services\CveNowService;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Support\Facades\Cache;
use Illuminate\View\View;
use Livewire\Component;

class Vulnerabilities extends Component
{
    use AuthorizesRequests;

    public Server $server;

    public string $additionalPackages = '';

    public int $page = 1;

    public function mount(string $server_uuid): void
    {
        $this->server = Server::ownedByCurrentTeam()->whereUuid($server_uuid)->firstOrFail();
        $this->authorize('viewSecurity', $this->server);
        $this->additionalPackages = app(CveNowService::class)->settings($this->server)['packages'] ?? '';
    }

    public function refreshReport(): void
    {
        $this->authorize('update', $this->server);
        if (! config('services.cve_now.enabled')) {
            $this->addError('monitoring', 'Vulnerability monitoring is disabled for this installation.');

            return;
        }
        if (Cache::add('cve-now:pending:'.$this->server->uuid, true, 1800)) {
            ServerVulnerabilityCheckJob::dispatch($this->server);
        }
    }

    public function savePackages(): void
    {
        $this->authorize('update', $this->server);
        $this->validate(['additionalPackages' => ['string', 'max:30000']]);
        try {
            app(CveNowService::class)->savePackages($this->server, $this->additionalPackages);
            $this->refreshReport();
        } catch (\InvalidArgumentException $exception) {
            $this->addError('additionalPackages', $exception->getMessage());
        }
    }

    public function render(): View
    {
        $this->authorize('viewSecurity', $this->server);
        $report = app(CveNowService::class)->report($this->server);
        $pages = max(1, (int) ceil(count($report['findings'] ?? []) / 25));
        $page = max(1, min($pages, $this->page));

        return view('livewire.server.security.vulnerabilities', ['report' => $report, 'page' => $page, 'pages' => $pages, 'pending' => Cache::has('cve-now:pending:'.$this->server->uuid), 'enabled' => (bool) config('services.cve_now.enabled')]);
    }
}
