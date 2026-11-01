<div wire:poll.30s>
    <x-slot:title>{{ $server->name }} > Source scanning | racconify</x-slot>
    <livewire:server.navbar :server="$server" />
    <div class="server-settings-workspace application-settings-workspace mt-4 grid w-full min-w-0 gap-8 lg:mt-0 xl:grid-cols-[210px_minmax(0,1fr)]">
        <x-server.sidebar :server="$server" activeMenu="security" />
        <div class="application-settings-form flex min-w-0 flex-col gap-6">
            <x-application.settings-section title="Source scanning" helper="Review potential weaknesses in your applications' GitHub source.">
                <x-slot:actions><x-forms.button wire:click="scan" :disabled="$pending || !$enabled">{{ $pending ? 'Scan in progress' : 'Scan now' }}</x-forms.button></x-slot:actions>
                @if (!$enabled)<x-callout type="warning" title="Source scanning is disabled for this installation" />@endif
                <p class="text-sm text-neutral-600 dark:text-fg-dim">Scans run daily and on demand, using the last successful deployed commit when recorded. Otherwise they resolve the configured reference. Each repository and reference is scanned once per server. Source stays on your server and is scanned without network access or running application code.</p>
                <p class="mt-3 text-sm text-neutral-600 dark:text-fg-dim">Findings are candidates for review, not confirmed vulnerabilities. This does not block deployments or change CVE alerts. Review the source and rule before deciding whether a finding is exploitable.</p>
                @if ($report['error'] ?? null)<x-callout type="danger" :title="$report['error']" />@endif
                @if ($report['attempted_at'] ?? null)<p class="mt-3 text-xs">Last scan attempt {{ \Illuminate\Support\Carbon::parse($report['attempted_at'])->diffForHumans() }}.</p>@else<x-empty size="sm" title="No source scan yet" description="Scan now to check connected GitHub applications." icon-name="shield-alert" />@endif
            </x-application.settings-section>
            <x-application.settings-section title="Repository coverage" helper="A completed scan means the selected rules ran. It does not certify that an application is safe.">
                @forelse ($report['repositories'] ?? [] as $repository)
                    <div class="border-b border-neutral-200 py-3 text-sm dark:border-white/[0.08]">
                        <p class="font-medium break-words">{{ $repository['repository'] }} · {{ $repository['status'] }}</p>
                        <p class="mt-1 text-xs">{{ implode(', ', $repository['applications']) }}</p>
                        <p class="mt-1 text-xs break-words">{{ $repository['ref_kind'] }}: {{ $repository['ref'] }}</p>
                        @if ($repository['commit'] ?? null)<p class="mt-1 text-xs break-words font-mono">Scanned commit: {{ $repository['commit'] }}</p>@endif
                        @if ($repository['checked_at'] ?? null)<p class="mt-1 text-xs">Results from {{ \Illuminate\Support\Carbon::parse($repository['checked_at'])->diffForHumans() }}. {{ $repository['files_scanned'] ?? 0 }} files checked · {{ $repository['finding_count'] ?? 0 }} candidates · {{ $repository['error_count'] ?? 0 }} scanner errors · {{ $repository['skipped_files'] ?? 0 }} files omitted by limits.</p>@endif
                        @if ($repository['unscanned_files'] ?? 0)<p class="mt-1 text-xs text-warning">{{ $repository['unscanned_files'] }} selected source files were not analyzed by the engine.</p>@endif
                        @if ($repository['error'] ?? null)<p class="mt-2 text-xs text-warning">{{ $repository['error'] }}</p>@endif
                        @if (($repository['status'] === 'partial') || ($repository['truncated'] ?? false))<p class="mt-2 text-xs text-warning">Coverage is incomplete. Some files, rules or results were omitted. Review repository size, syntax errors and scanner limits.</p>@endif
                        @if (isset($repository['checked_at']) && \Illuminate\Support\Carbon::parse($repository['checked_at'])->lt(now()->subDays(2)))<p class="mt-2 text-xs text-warning">These results are stale. Run a new scan.</p>@endif
                        @if ($repository['engine'] ?? null)<p class="mt-1 text-xs">{{ $repository['engine'] }} · {{ $repository['rule_count'] }} rules · {{ implode(', ', $repository['languages']) }}</p>@endif
                    </div>
                @empty
                    <p class="text-sm">No scanned repositories.</p>
                @endforelse
                @if ($report['unsupported'] ?? [])<p class="mt-3 text-sm">Applications without supported GitHub source: {{ implode(', ', $report['unsupported']) }}.</p>@endif
            </x-application.settings-section>
            <x-application.settings-section title="Potential weaknesses" :helper="$findingCount.' stored candidates. Open the exact scanned commit to review each match.'">
                @forelse ($findings as $finding)
                    <details wire:ignore.self class="border-b border-neutral-200 py-3 dark:border-white/[0.08]" wire:key="source-{{ $finding['fingerprint'] }}-{{ $finding['repository'] }}-{{ $finding['commit'] }}">
                        <summary class="cursor-pointer text-sm break-words">{{ $finding['severity'] }} · {{ $finding['path'] }}:{{ $finding['line'] }}{{ $finding['stale'] ? ' · Previous scan' : '' }}</summary>
                        <p class="mt-2 text-xs break-words">{{ $finding['repository'] }} · {{ $finding['message'] }}</p>
                        <div class="mt-2 flex flex-wrap gap-3 text-xs">
                            <a class="underline" href="{{ 'https://github.com/'.$finding['repository'].'/blob/'.$finding['commit'].'/'.implode('/', array_map('rawurlencode', explode('/', $finding['path']))).'#L'.$finding['line'] }}" target="_blank" rel="noopener noreferrer">Review source</a>
                            <a class="underline" href="{{ $finding['rule_url'] }}" target="_blank" rel="noopener noreferrer">Rule and remediation</a>
                            @foreach ($finding['cwes'] as $cwe)<a class="underline" href="{{ 'https://cwe.mitre.org/data/definitions/'.substr($cwe, 4).'.html' }}" target="_blank" rel="noopener noreferrer">{{ $cwe }}</a>@endforeach
                        </div>
                    </details>
                @empty
                    <p class="text-sm">No stored candidates. Check repository coverage above before interpreting this result.</p>
                @endforelse
                @if ($pages > 1)<div class="mt-3 flex items-center gap-3"><x-forms.button wire:click="$set('page', {{ max(1, $page - 1) }})" :disabled="$page === 1">Previous</x-forms.button><span class="text-xs">{{ $page }} / {{ $pages }}</span><x-forms.button wire:click="$set('page', {{ min($pages, $page + 1) }})" :disabled="$page === $pages">Next</x-forms.button></div>@endif
            </x-application.settings-section>
            <x-callout type="info" title="Scope and limits">
                <a class="underline" href="https://github.com/opengrep/opengrep" target="_blank" rel="noopener noreferrer">Opengrep</a> runs a pinned selection of MIT-licensed <a class="underline" href="https://gitlab.com/gitlab-org/security-products/sast-rules" target="_blank" rel="noopener noreferrer">GitLab SAST rules</a> for JavaScript, TypeScript, C# and Python on Linux x86-64 servers. Other architectures and languages, container-only services, submodules, symlinks, dependencies and generated output are outside this scan. Files over 1 MB and source beyond 200 MB or 30,000 selected files are omitted. Scans have a time limit. Source snippets and secrets are not included in reports. This is pattern and local taint analysis, with no guarantee of finding every weakness. CWE labels describe weakness types; <a class="underline" href="{{ asset('cwe-terms.txt') }}" target="_blank" rel="noopener noreferrer">CWE terms of use</a> apply.
            </x-callout>
        </div>
    </div>
</div>
