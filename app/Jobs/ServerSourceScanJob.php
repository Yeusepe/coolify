<?php

namespace App\Jobs;

use App\Models\Server;
use App\Services\SourceScanService;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Queue\Middleware\WithoutOverlapping;
use Illuminate\Support\Facades\Cache;

class ServerSourceScanJob implements ShouldQueue
{
    use Queueable;

    public int $timeout = 2700;

    public int $tries = 1;

    public function __construct(public Server $server)
    {
        $this->onQueue(maintenance_queue());
    }

    public function middleware(): array
    {
        return [(new WithoutOverlapping('source-scan:'.$this->server->uuid))->expireAfter(2800)->dontRelease()];
    }

    public function handle(SourceScanService $service): void
    {
        try {
            if (config('services.source_scanning.enabled') && $this->server->isFunctional()) {
                Cache::put('source-scan:pending:'.$this->server->uuid, true, 2800);
                $service->saveReport($this->server, $service->collect($this->server));
            }
        } catch (\Throwable) {
            $service->saveReport($this->server, [...$service->report($this->server), 'error' => 'Source scan failed. Previous findings are retained.', 'attempted_at' => now()->toIso8601String()]);
        } finally {
            Cache::forget('source-scan:pending:'.$this->server->uuid);
        }
    }
}
