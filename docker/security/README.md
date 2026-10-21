# Security images, 20 October 2026

These images preserve the existing application versions while updating vulnerable
runtimes, operating-system packages, and certificate trust. Production uses the
published image digests; rebuilding a dated tag cannot change a running deployment.

- `security-runtime.yml`: Bun's upstream certificate fix at revision
  `9b4284f788f20e3d6ec8358daf62ad10694b158a`. This is a temporary prerelease;
  replace it with a tested stable release containing the fix. The downloaded
  upstream binary is verified by SHA-256 and the build fails if its content changes.
- `security-php.yml`: ServerSideUp v4.5.1 source rebuilt with PHP 8.4.26, preserving
  the v4 S6 startup layout. PHP announced another critical release for
  21 October 2026, 14:00 UTC; that unpublished release is not included here.
- `security-minio.yml`: MinIO/MC's existing public source releases rebuilt with
  Go 1.27.3 and patched dependencies. Corresponding source archives, including
  updated module locks, are included under `/usr/share/minio/source` in the image.
- `security-redis.yml`: the same Redis Stack release with Ubuntu security updates.
- `security-studio.yml`: the pinned public Supabase source with Next.js 16.4.2,
  React 19.3.1, Node 22.23.3, and OS security updates. The generated dependency
  lockfile is retained as a workflow artifact. This is a custom build, not an
  official Supabase release.

The public CA bundle excludes emSign ECC Root G3 and Comodo AAA to reject both
known chains containing the compromised eMudhra intermediate. It retains other
unrelated roots. Node uses OpenSSL's CA store; Erlang services must mount the
bundle at their OS trust path because they ignore `SSL_CERT_FILE`.

When updating these images, repeat negative TLS checks against both researcher
test hosts and a positive HTTPS check, then run the application/integration tests.
Keep source-version changes separate from persistent database major upgrades.

References: [eMudhra incident](https://emudhra.we-have-a-problem.com/),
[Bun fix](https://github.com/oven-sh/bun/pull/46159),
[Next.js advisory](https://nextjs.org/blog/nextjs-security-update-october-14-2026),
[PHP announcement](https://www.php.net/archive/2026.php#2026-10-20-1).
