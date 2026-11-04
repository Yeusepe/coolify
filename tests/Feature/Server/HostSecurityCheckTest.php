<?php

use App\Actions\Server\CheckHostSecurity;
use App\Actions\Server\CheckUpdates;
use App\Models\InstanceSettings;
use App\Models\PrivateKey;
use App\Models\Server;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Storage;

uses(RefreshDatabase::class);

beforeEach(function () {
    Server::flushIdentityMap();
    Storage::fake('ssh-keys');
    Storage::fake('ssh-mux');
    config()->set('constants.ssh.max_retries', 1);
    config()->set('constants.ssh.mux_enabled', false);
    InstanceSettings::forceCreate(['id' => 0]);
});

function hostSecurityServer(): Server
{
    $team = User::factory()->create()->teams()->first();

    return Server::factory()->create([
        'team_id' => $team->id,
        'private_key_id' => PrivateKey::factory()->create(['team_id' => $team->id])->id,
    ]);
}

it('uses distro tools and keeps their reports without comparing upstream versions', function (string $os, string $manager, string $command, string $report) {
    $server = hostSecurityServer();
    fakeRemoteProcesses([
        '*uname -r*' => Process::result(output: "6.12.107-amd64\nlinux-image-6.12.107-amd64 6.12.107-1"),
        '*'.$command.'*' => Process::result(output: $report),
    ]);

    $result = CheckHostSecurity::run($server, $os, $manager, 'trixie');

    expect($result)->toMatchArray([
        'running_kernel' => '6.12.107-amd64',
        'kernel_package' => 'linux-image-6.12.107-amd64 6.12.107-1',
        'report' => $report,
        'cves' => ['CVE-2026-98432'],
        'error' => null,
    ]);
    Process::assertRan(fn ($process) => str_contains(remoteProcessScript($process), $command));
})->with([
    ['debian', 'apt', 'debsecan', "CVE-2026-98432 linux-image-6.12.107-amd64\nCVE-2026-98432 linux-headers-amd64"],
    ['ubuntu', 'apt', 'pro cves', 'linux-image-generic critical standard CVE-2026-98432'],
    ['rocky', 'dnf', 'dnf updateinfo list --security --with-cve --available', 'CVE-2026-98432 Important/Sec. kernel-core-5.14.0-611.el9.x86_64'],
]);

it('reports a missing or failed advisory tool without declaring the host unaffected', function () {
    $server = hostSecurityServer();
    fakeRemoteProcesses([
        '*uname -r*' => Process::result(output: '6.12.107-custom'),
        '*debsecan*' => Process::result(errorOutput: 'debsecan: command not found', exitCode: 127),
    ]);

    $result = CheckHostSecurity::run($server, 'debian', 'apt', 'trixie');

    expect($result['error'])->toContain('debsecan')
        ->and($result['report'])->toBeNull()
        ->and($result['cves'])->toBe([])
        ->and($result['kernel_package'])->toBeNull();
});

it('marks unsupported advisory coverage explicitly while still recording the running kernel', function () {
    $server = hostSecurityServer();
    fakeRemoteProcesses(['*uname -r*' => Process::result(output: '6.12.107-custom')]);

    $result = CheckHostSecurity::run($server, 'alpine', 'apk', '');

    expect($result['running_kernel'])->toBe('6.12.107-custom')
        ->and($result['source'])->toBeNull()
        ->and($result['error'])->toContain('not supported')
        ->and($result['report'])->toBeNull();
});

it('does not use Debian advisories for Debian derivatives or an unknown suite', function (string $os, string $suite) {
    $server = hostSecurityServer();
    Process::fake();

    $result = CheckHostSecurity::run($server, $os, 'apt', $suite);

    expect($result['error'])->not->toBeNull();
    Process::assertDidntRun(fn ($process) => str_contains(remoteProcessScript($process), 'debsecan'));
})->with([['raspbian', 'bookworm'], ['debian', '']]);

it('preserves a successful advisory report when the running kernel cannot be identified', function () {
    $server = hostSecurityServer();
    fakeRemoteProcesses([
        '*uname -r*' => Process::result(errorOutput: 'permission denied', exitCode: 1),
        '*pro cves*' => Process::result(output: 'No CVEs affect installed packages.'),
    ]);

    $result = CheckHostSecurity::run($server, 'ubuntu', 'apt', 'noble');

    expect($result['running_kernel'])->toBeNull()
        ->and($result['kernel_package'])->toBeNull()
        ->and($result['report'])->toBe('No CVEs affect installed packages.');
});

it('includes native advisory results and reboot states in the existing host patch check', function (string $status, ?bool $required, bool $livepatched) {
    $server = hostSecurityServer();
    $server->settings->update(['is_reachable' => true, 'is_usable' => true]);
    fakeRemoteProcesses([
        '*cat /etc/os-release*' => Process::result(output: "ID=debian\nVERSION_CODENAME=trixie"),
        '*REBOOT=*' => Process::result(output: 'REBOOT='.$status),
    ]);
    CheckHostSecurity::shouldRun()->once()->withArgs(fn ($host, $os, $manager, $suite) => $host->id === $server->id && $os === 'debian' && $manager === 'apt' && $suite === 'trixie')
        ->andReturn(['cves' => ['CVE-2026-98432'], 'error' => null]);

    $result = CheckUpdates::run($server);

    expect($result['host_security']['cves'])->toBe(['CVE-2026-98432'])
        ->and($result['reboot_required'])->toBe($required)
        ->and($result['kernel_livepatched'])->toBe($livepatched);
})->with([
    ['yes', true, false],
    ['no', false, false],
    ['unknown', null, false],
    ['yes-kernel-livepatches-applied', true, true],
]);

it('runs the kernel and advisory checks with sudo for a non-root SSH user', function (string $os, string $manager, string $command) {
    $server = hostSecurityServer();
    $server->update(['user' => 'ubuntu']);
    Process::fake();

    CheckHostSecurity::run($server->fresh(), $os, $manager, 'trixie');

    Process::assertRan(fn ($process) => str_contains(remoteProcessScript($process), 'sudo '.CheckHostSecurity::KERNEL_CHECK_COMMAND));
    Process::assertRan(fn ($process) => str_contains(remoteProcessScript($process), 'sudo LANG=C '.$command));
})->with([
    ['ubuntu', 'apt', 'pro cves'],
    ['debian', 'apt', 'debsecan'],
    ['rocky', 'dnf', 'dnf updateinfo list'],
]);

it('reuses the DNF advisory result for package security flags without a second scan', function (?string $error, ?int $count) {
    $server = hostSecurityServer();
    $server->settings->update(['is_reachable' => true, 'is_usable' => true]);
    fakeRemoteProcesses([
        '*cat /etc/os-release*' => Process::result(output: 'ID=rocky'),
        '*dnf repoquery*' => Process::result(output: 'openssl x86_64 3.5.8-2.el9 baseos'),
        '*rpm -qa*' => Process::result(output: 'openssl x86_64 3.5.8-1.el9'),
    ]);
    CheckHostSecurity::shouldRun()->once()->andReturn([
        'cves' => $error === null ? ['CVE-2026-98432'] : [],
        'report' => $error === null ? 'CVE-2026-98432 Important/Sec. openssl-3.5.8-2.el9.x86_64' : null,
        'error' => $error,
    ]);

    $result = CheckUpdates::run($server);

    expect($result['security_updates'])->toBe($count)
        ->and($result['host_security']['error'])->toBe($error)
        ->and($result)->not->toHaveKey('error');
    Process::assertDidntRun(fn ($process) => str_contains(remoteProcessScript($process), 'dnf updateinfo'));
})->with([[null, 1], ['Advisories unavailable', null]]);
