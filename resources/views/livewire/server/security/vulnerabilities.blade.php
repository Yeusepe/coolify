<div wire:poll.30s>
    <x-slot:title>{{ $server->name }} > Vulnerabilities | racconify</x-slot>
    <livewire:server.navbar :server="$server" />
    <div class="server-settings-workspace application-settings-workspace mt-4 grid w-full min-w-0 gap-8 lg:mt-0 xl:grid-cols-[210px_minmax(0,1fr)]">
        <x-server.sidebar :server="$server" activeMenu="security" />
        <div class="application-settings-form flex min-w-0 flex-col gap-6">
            <x-application.settings-section title="Vulnerabilities" helper="Installed software checked against CVE.now.">
                <x-slot:actions><x-forms.button wire:click="refreshReport" :disabled="$pending || !$enabled">{{ $pending ? 'Check in progress' : 'Check now' }}</x-forms.button></x-slot:actions>
                @error('monitoring')<x-callout type="warning" :title="$message" />@enderror
                @if (!$enabled)<x-callout type="warning" title="Monitoring is disabled for this installation" />@endif
                <p class="text-sm text-neutral-600 dark:text-fg-dim">Automatic checks run hourly. New high and critical version matches use your existing server patch notification channels. Advisories with uncertain version applicability stay on this page without triggering alerts. Names and versions are sent to CVE.now. Credentials, source code and lockfiles are not uploaded.</p>
                @if ($report['error'] ?? null)<x-callout type="danger" title="Check could not finish">{{ $report['error'] }} Last successful results remain below.</x-callout>@endif
                @if (isset($report['checked_at']))
                    <p class="mt-3 text-sm text-neutral-600 dark:text-fg-dim">Checked {{ \Illuminate\Support\Carbon::parse($report['checked_at'])->diffForHumans() }}. {{ $report['packages_checked'] }} distinct package versions checked across {{ count($report['containers']) }} containers.</p>
                    @if (\Illuminate\Support\Carbon::parse($report['checked_at'])->lt(now()->subHours(3)))<x-callout type="warning" title="These results are stale. Run a new check." />@endif
                @else
                    <x-empty size="sm" title="No completed check yet" description="Run a check to discover installed packages and review relevant advisories." icon-name="shield-alert" />
                @endif
            </x-application.settings-section>
            @if (isset($report['checked_at']))
                @if (isset($report['software']))
                    <x-application.settings-section title="Detected software and update recommendations" helper="Vendor releases are checked for the installed release line. Recommendations never change software automatically.">
                        @if (!empty($report['host']))<p class="mb-3 text-xs text-neutral-600 dark:text-fg-dim">{{ $report['host']['os'] ?? '' }} · Kernel {{ $report['host']['kernel'] ?? '' }}</p>@endif
                        @forelse ($report['software'] as $software)
                            <details class="border-b border-neutral-200 py-3 dark:border-white/[0.08]" wire:key="software-{{ hash('sha256', $software['technology'].$software['version']) }}">
                                <summary class="cursor-pointer text-sm"><span class="font-medium">{{ $software['name'] }} {{ $software['version'] }}</span> · {{ $software['status'] }}{{ $software['target'] ? '. Vendor target: '.$software['target'] : '' }}</summary>
                                <p class="mt-2 break-words text-xs">{{ implode(', ', $software['contexts']) }}</p>
                                <p class="mt-2 text-xs text-neutral-600 dark:text-fg-dim">{{ $software['recommendation'] }}</p>
                                @if ($software['url'])<a class="mt-2 inline-block text-xs underline" href="{{ $software['url'] }}" target="_blank" rel="noopener noreferrer">Official releases</a>@endif
                            </details>
                        @empty
                            <p class="text-sm">No supported runtime or framework version was detected. Review the running resources below.</p>
                        @endforelse
                    </x-application.settings-section>
                    <x-application.settings-section title="Security dependency update plan" helper="Advisory fix versions grouped by affected application. Confirm vendor applicability before upgrading.">
                        @forelse ($report['package_updates'] ?? [] as $update)
                            <details class="border-b border-neutral-200 py-3 dark:border-white/[0.08]" wire:key="package-update-{{ hash('sha256', $update['ecosystem'].$update['package'].$update['version']) }}">
                                <summary class="cursor-pointer text-sm"><span class="font-medium">{{ $update['package'] }} {{ $update['version'] }}</span> · {{ $update['status'] }}{{ $update['target'] ? '. Candidate: '.$update['target'] : '. No verified target.' }}</summary>
                                <p class="mt-2 break-words text-xs">{{ implode(', ', $update['contexts']) }}</p>
                                <p class="mt-2 text-xs text-neutral-600 dark:text-fg-dim">{{ $update['recommendation'] }}</p>
                                <div class="mt-2 flex flex-wrap gap-2 text-xs">@foreach ($update['advisories'] as $advisory)<a class="underline" href="{{ $advisory['url'] }}" target="_blank" rel="noopener noreferrer">{{ $advisory['id'] }}</a>@endforeach</div>
                            </details>
                        @empty
                            <p class="text-sm">No dependency fix plan was generated from the checked advisories. This does not certify that the dependencies are safe.</p>
                        @endforelse
                    </x-application.settings-section>
                    <x-application.settings-section title="Running applications and infrastructure" helper="Resources mapped to their racconify names. Detected packages may include optional or build-time dependencies.">
                        @foreach ($report['resources'] ?? [] as $resource)
                            <details class="border-b border-neutral-200 py-3 dark:border-white/[0.08]" wire:key="running-resource-{{ hash('sha256', $resource['name']) }}">
                                <summary class="cursor-pointer text-sm font-medium">{{ $resource['resource'] ?? $resource['name'] }}</summary>
                                <p class="mt-2 break-words text-xs">{{ $resource['software'] ? implode(', ', $resource['software']) : 'No supported software version detector matched this image. Manual vendor review is required.' }}</p>
                                <p class="mt-2 break-words font-mono text-xs text-neutral-600 dark:text-fg-dim">Image: {{ $resource['image'] }}</p>
                            </details>
                        @endforeach
                    </x-application.settings-section>
                @endif
                <x-application.settings-section title="Advisory matches" helper="Version matches require deployment and vendor-backport review. No packages are changed automatically.">
                    @forelse (array_slice($report['findings'], ($page - 1) * 25, 25) as $finding)
                        <div class="border-b border-neutral-200 py-4 last:border-0 dark:border-white/[0.08]" wire:key="{{ hash('sha256', $finding['id'].$finding['ecosystem'].$finding['package'].$finding['version']) }}">
                            <div class="flex flex-wrap items-center justify-between gap-2"><a class="font-medium underline" href="{{ $finding['url'] }}" target="_blank" rel="noopener noreferrer">{{ $finding['id'] }}</a><span class="font-mono text-xs">CVSS {{ $finding['score'] ?: 'Unscored' }}</span></div>
                            <p class="mt-1 text-sm">{{ $finding['title'] }}</p>
                            <p class="mt-2 break-words font-mono text-xs">{{ $finding['package'] }} {{ $finding['version'] }} · {{ implode(', ', $finding['contexts']) }}</p>
                            <p class="mt-1 text-xs text-neutral-600 dark:text-fg-dim">{{ $finding['kind'] }}. {{ $finding['fixed'] ? 'Advisory fix versions: '.implode(', ', $finding['fixed']) : 'No fix version supplied by this source.' }}</p>
                        </div>
                    @empty
                        <x-empty size="sm" title="No matches in the checked inventory" description="This does not certify that the server is vulnerability-free. Coverage depends on inventory and published version data." icon-name="check-circle" />
                    @endforelse
                    <div class="mt-4 flex items-center justify-between gap-3 text-sm">
                        <x-forms.button wire:click="$set('page', {{ $page - 1 }})" :disabled="$page <= 1">Previous</x-forms.button>
                        <span>Page {{ $page }} of {{ $pages }}. {{ count($report['findings']) }} matches.</span>
                        <x-forms.button wire:click="$set('page', {{ $page + 1 }})" :disabled="$page >= $pages">Next</x-forms.button>
                    </div>
                </x-application.settings-section>
                <x-application.settings-section title="Detected runtimes" helper="Versions read from the running server and containers.">
                    @foreach ($report['runtimes'] as $runtime)<p class="break-words py-1 font-mono text-xs">{{ $runtime['container'] }} · {{ $runtime['name'] }} {{ $runtime['version'] }}</p>@endforeach
                </x-application.settings-section>
            @endif
            <x-application.settings-section title="Additional technologies" helper="Track exact package releases outside the detected containers. One ecosystem:package@version per line.">
                <form wire:submit="savePackages" class="flex flex-col gap-3">
                    <x-forms.textarea id="additionalPackages" wire:model="additionalPackages" label="Packages" placeholder="npm:next@16.4.2" />
                    <p class="text-xs text-neutral-600 dark:text-fg-dim">Supported: npm, packagist, pypi, nuget, go, crates.io, rubygems and maven.</p>
                    <x-forms.button type="submit">Save and check</x-forms.button>
                </form>
            </x-application.settings-section>
            <x-callout type="info" title="Coverage and source">
                Checks cover discovered npm, Composer and NuGet packages, plus recent critical PHP, Node.js, Docker, PostgreSQL, Redis, Nginx and OpenSSL runtime advisories. Vendor release recommendations also cover detected Bun, ASP.NET Core, MongoDB, proxies and other supported software. A newer release is not proof of a vulnerability; an older version may include distribution backports. Unidentified binaries and compiled dependencies are not fully covered. Use <a class="underline" href="{{ route('server.security.patches', ['server_uuid' => $server->uuid]) }}" {{ wireNavigate() }}>Server patching</a> for operating system updates. CVE.now merges advisory sources; its model-written summaries are not used to decide matches. <a class="underline" href="https://cve.now/" target="_blank" rel="noopener noreferrer">CVE.now</a> summaries are CC-BY 4.0. Uses NVD data; not endorsed by NVD.
                @foreach ($report['warnings'] ?? [] as $warning)<p>{{ $warning }}</p>@endforeach
            </x-callout>
        </div>
    </div>
</div>
