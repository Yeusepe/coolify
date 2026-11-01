import importlib.util
import contextlib
import io
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

root = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("source_snapshot", root / "scripts/source-scan.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class SourceSnapshotTest(unittest.TestCase):
    def test_budget_exhaustion_defers_without_attempting_the_repository(self):
        with tempfile.TemporaryDirectory() as temporary:
            request = pathlib.Path(temporary) / "request.json"
            request.write_text(json.dumps({"image": "ghcr.io/yeusepe/coolify@sha256:" + "a" * 64, "targets": [{"id": "later", "repository": "owner/app", "ref": "main"}]}))
            output = io.StringIO()
            with patch.object(runner.sys, "argv", ["runner", str(request)]), patch.object(runner, "run", return_value=b""), patch.object(runner, "scan") as scan, patch.object(runner.time, "monotonic", side_effect=[0, 2000]), contextlib.redirect_stdout(output):
                runner.main()
            self.assertEqual(json.loads(output.getvalue())["repositories"], [{"id": "later", "status": "deferred"}])
            scan.assert_not_called()
            self.assertFalse(request.exists())

    def test_files_omitted_by_the_engine_keep_coverage_partial(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(runner, "run", side_effect=[b"", b"", b"a" * 40, json.dumps({"format": 1, "status": "completed", "files_scanned": 1}).encode()]), patch.object(runner, "snapshot", return_value={"snapshot_files": 2, "snapshot_bytes": 30, "skipped_files": 0}), patch.object(runner.shutil, "rmtree"), patch.object(runner.subprocess, "run"):
            result = runner.scan({"repository": "owner/app", "ref": "main"}, "pinned-image", pathlib.Path(temporary), "")
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["unscanned_files"], 1)

    def test_rejects_untrusted_repositories_and_references(self):
        for value in ("../secret", "team/..", "https://evil.test/repo", "team/repo;id", "team/repo/extra"):
            with self.assertRaises(ValueError):
                runner.repository(value)
        for value in ("--upload-pack=evil", "../main", "main..branch", "main.lock", "main//other"):
            with self.assertRaises(ValueError):
                runner.reference(value)
        self.assertEqual(runner.reference("feature/security"), "refs/heads/feature/security")

    def test_snapshot_ignores_repository_suppressions_and_never_copies_credentials_or_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = pathlib.Path(temporary) / "repo"
            repo.mkdir()
            def git(*args):
                return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL)
            git("init")
            git("config", "user.email", "fixture@example.test")
            git("config", "user.name", "Fixture")
            (repo / "app.ts").write_text("eval(input); // nosemgrep")
            (repo / ".gitattributes").write_text("app.ts export-ignore\n")
            (repo / ".semgrepignore").write_text("*\n")
            (repo / ".env").write_text("PRIVATE_SECRET=secret")
            (repo / "node_modules").mkdir()
            (repo / "node_modules" / "dependency.js").write_text("eval(input)")
            os.symlink("/etc/passwd", repo / "linked.ts")
            (repo / "oversize.js").write_bytes(b"x" * 1_000_001)
            git("add", ".")
            git("commit", "-m", "Fixture")
            (repo / ".git" / "FETCH_HEAD").write_bytes(git("rev-parse", "HEAD"))
            destination = pathlib.Path(temporary) / "snapshot"
            destination.mkdir()
            result = runner.snapshot(["git", "--git-dir=" + str(repo / ".git")], destination, os.environ.copy())
            self.assertEqual([str(p.relative_to(destination)) for p in destination.rglob("*") if p.is_file()], ["app.ts"])
            self.assertEqual((destination / "app.ts").read_text(), "eval(input); // nosemgrep")
            self.assertEqual(result["skipped_files"], 2)
            self.assertEqual(result["snapshot_files"], 1)


if __name__ == "__main__":
    unittest.main()
