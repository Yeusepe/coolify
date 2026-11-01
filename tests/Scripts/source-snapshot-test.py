import importlib.util
import os
import pathlib
import subprocess
import tempfile
import unittest

root = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("source_snapshot", root / "scripts/source-scan.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class SourceSnapshotTest(unittest.TestCase):
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
