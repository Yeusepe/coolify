<?php

use App\Services\SourceScanService;

it('accepts only normalized GitHub repositories', function () {
    $service = app(SourceScanService::class);
    expect($service->repository('git@github.com:Yeusepe/app.git'))->toBe('Yeusepe/app');
    expect($service->repository('https://github.com/Yeusepe/app'))->toBe('Yeusepe/app');
    foreach (['https://other.test/app', 'git@other.test:team/app', 'team/..', '../app', 'https://token@github.com/team/app', 'team/app;id'] as $value) {
        expect($service->repository($value))->toBeNull();
    }
});

it('retains previous findings and commit on a failed attempt without retaining credentials', function () {
    $service = app(SourceScanService::class);
    $old = ['id' => 'old', 'repository' => 'owner/app', 'commit' => str_repeat('a', 40), 'checked_at' => '2026-10-30T00:00:00Z', 'findings' => [['path' => 'app.ts', 'line' => 7]]];
    $inventory = ['targets' => [['id' => 'new', 'repository' => 'owner/app', 'ref' => str_repeat('b', 40), 'token' => 'PRIVATE_TOKEN', 'private_key' => 'PRIVATE_KEY', 'applications' => ['API']]], 'unsupported' => ['Image only']];
    $report = $service->merge(['repositories' => [$old]], $inventory, []);
    expect($report['repositories'][0])->toMatchArray(['status' => 'failed', 'commit' => str_repeat('a', 40), 'ref' => str_repeat('b', 40), 'findings' => $old['findings']]);
    expect(json_encode($report))->not->toContain('PRIVATE');
    expect($report['unsupported'])->toBe(['Image only']);
});

it('keeps partial coverage explicit and replaces old results only with a new result', function () {
    $service = app(SourceScanService::class);
    $report = $service->merge([], ['targets' => [['id' => 'one', 'repository' => 'owner/app']], 'unsupported' => []], ['one' => ['id' => 'one', 'status' => 'partial', 'commit' => str_repeat('c', 40), 'files_scanned' => 0, 'findings' => []]]);
    expect($report['repositories'][0]['status'])->toBe('partial');
    expect($report['repositories'][0]['files_scanned'])->toBe(0);
    expect($report['repositories'][0])->toHaveKey('checked_at');
});
