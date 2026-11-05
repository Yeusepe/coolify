<?php

namespace App\Actions\Server;

use App\Models\Server;
use Lorisleiva\Actions\Concerns\AsAction;

class CheckHostSecurity
{
    use AsAction;

    public const KERNEL_CHECK_COMMAND = <<<'SH'
sh -c 'kernel=$(uname -r) || exit 1
printf "%s\n" "$kernel"
if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f="\${db:Status-Status} \${binary:Package} \${Version}\n" "linux-image-$kernel" "linux-image-unsigned-$kernel" 2>/dev/null | sed -n "s/^installed //p"
elif command -v rpm >/dev/null 2>&1; then
    package=$(rpm -q --whatprovides "kernel-uname-r = $kernel" --qf "%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n" 2>/dev/null) && printf "%s\n" "$package"
fi
exit 0'
SH;

    public function handle(Server $server, string $osId, string $packageManager, string $suite): array
    {
        $kernel = explode("\n", (string) instant_remote_process([self::KERNEL_CHECK_COMMAND], $server, false, timeout: 30, maxAttempts: 1), 2);
        $result = [
            'running_kernel' => filled($kernel[0]) ? $kernel[0] : null,
            'kernel_package' => filled($kernel[1] ?? null) ? $kernel[1] : null,
            'source' => null,
            'report' => null,
            'cves' => [],
            'error' => null,
        ];

        // DNF incluye el running kernel aunque ya haya uno nuevo instalado
        // https://github.com/rpm-software-management/dnf/blob/master/dnf/cli/commands/updateinfo.py
        [$source, $command] = match (true) {
            $osId === 'debian' && $suite !== '' => ['Debian security tracker (debsecan)', 'debsecan --format summary --suite '.escapeshellarg($suite)],
            $osId === 'ubuntu' => ['Ubuntu security notices (pro cves)', 'pro cves'],
            $packageManager === 'dnf' => ['Distribution repository advisories (dnf)', 'dnf updateinfo list --security --with-cve --available'],
            default => [null, null],
        };
        $result['source'] = $source;

        if ($command === null) {
            $result['error'] = 'Host CVE checks are not supported for this distribution. Package update checks still run.';

            return $result;
        }

        try {
            $result['report'] = (string) instant_remote_process(['LANG=C '.$command], $server, timeout: 180, maxAttempts: 1);
            preg_match_all('/\bCVE-[0-9]{4}-[0-9]{4,}\b/', $result['report'], $matches);
            $result['cves'] = array_values(array_unique($matches[0]));
        } catch (\Throwable $e) {
            $result['error'] = 'Host CVE check failed. Ensure the distro tool is installed and can fetch advisories: '.$e->getMessage();
        }

        return $result;
    }
}
