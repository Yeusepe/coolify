"""Fetch immutable GitHub snapshots and scan without running repository code."""
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import uuid

EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".cs", ".py"}
EXCLUDED = {"node_modules", "vendor", ".git", "dist", "build", ".next", "coverage", "bin", "obj", ".venv", "venv"}
LIMIT = 200_000_000


def run(command, env=None, timeout=120, input=None):
    return subprocess.run(command, input=input, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env=env, timeout=timeout, check=True).stdout


def repository(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        raise ValueError("Unsupported repository")
    if any(part in {".", ".."} for part in value.split("/")):
        raise ValueError("Unsupported repository")
    return value


def reference(value):
    if re.fullmatch(r"[0-9a-f]{40}", value):
        return value
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]{0,199}", value) or any(
        part in {"", ".", ".."} or part.endswith((".", ".lock")) for part in value.split("/")
    ) or ".." in value:
        raise ValueError("Unsupported branch")
    return "refs/heads/" + value


def snapshot(git, destination, env):
    entries = run([*git, "ls-tree", "-r", "-z", "-l", "FETCH_HEAD"], env=env).split(b"\0")
    selected, skipped, total = [], 0, 0
    for entry in entries:
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, kind, identifier, size = metadata.split()
        path = pathlib.PurePosixPath(raw_path.decode("utf-8", errors="strict"))
        if path.is_absolute() or ".." in path.parts or any(ord(c) < 32 for c in str(path)):
            raise ValueError("Unsafe repository path")
        if any(part in EXCLUDED for part in path.parts) or path.suffix.lower() not in EXTENSIONS:
            continue
        if mode not in {b"100644", b"100755"} or kind != b"blob":
            skipped += 1
            continue
        length = int(size)
        if length > 1_000_000 or total + length > LIMIT or len(selected) >= 30000:
            skipped += 1
            continue
        total += length
        selected.append((identifier, path, length))
    with subprocess.Popen([*git, "cat-file", "--batch"], env=env, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        for identifier, path, length in selected:
            process.stdin.write(identifier + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().split()
            if len(header) != 3 or header[1] != b"blob" or int(header[2]) != length:
                raise ValueError("Invalid repository blob")
            content = process.stdout.read(length)
            if len(content) != length or process.stdout.read(1) != b"\n":
                raise ValueError("Incomplete repository blob")
            target = destination.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            target.write_bytes(content)
            target.chmod(0o644)
        process.stdin.close()
        if process.wait(timeout=10) != 0:
            raise ValueError("Repository snapshot failed")
    return {"snapshot_files": len(selected), "snapshot_bytes": total, "skipped_files": skipped}


def scan(target, image, directory, host_keys):
    repo = repository(target["repository"])
    ref = reference(target["ref"])
    work = directory / uuid.uuid4().hex
    work.mkdir(mode=0o700)
    source = work / "source"
    source.mkdir(mode=0o755)
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": str(work),
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
           "GIT_ALLOW_PROTOCOL": "https:ssh", "LC_ALL": "C.UTF-8"}
    git = ["git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", "--git-dir=" + str(work / "repository.git")]
    url = "https://github.com/" + repo + ".git"
    if target.get("private_key"):
        key = work / "key"
        key.write_text(target["private_key"] + "\n")
        key.chmod(0o600)
        known = work / "known_hosts"
        known.write_text(host_keys)
        env["GIT_SSH_COMMAND"] = f"ssh -F /dev/null -i {key} -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile={known}"
        url = "git@github.com:" + repo + ".git"
    elif target.get("token"):
        secret = work / "credential"
        secret.write_text(target["token"])
        secret.chmod(0o600)
        askpass = work / "askpass"
        askpass.write_text("#!/bin/sh\ncase \"$1\" in *Username*) printf '%s' x-access-token;; *) cat " + str(secret) + ";; esac\n")
        askpass.chmod(0o700)
        env["GIT_ASKPASS"] = str(askpass)
    run([*git, "init", "--bare"], env=env)
    run([*git, "fetch", "--depth=1", "--no-tags", "--no-recurse-submodules", url, ref], env=env)
    commit = run([*git, "rev-parse", "FETCH_HEAD"], env=env).decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Invalid commit")
    coverage = snapshot(git, source, env)
    # Credentials and Git metadata never enter the scanner mount.
    for item in ("key", "credential", "askpass", "known_hosts"):
        (work / item).unlink(missing_ok=True)
    shutil.rmtree(work / "repository.git")
    name = "racconify-source-" + uuid.uuid4().hex
    try:
        raw = run(["docker", "run", "--rm", "--name", name, "--network", "none", "--read-only",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128",
                   "--memory", "2g", "--cpus", "2", "--tmpfs", "/tmp:rw,exec,nosuid,size=512m",
                   "--mount", f"type=bind,src={source},dst=/src,readonly", image], timeout=360)
        if len(raw) > 8_000_000:
            raise ValueError("Oversized scanner result")
        result = json.loads(raw)
        if result.get("format") != 1 or result.get("status") not in {"completed", "partial", "failed"}:
            raise ValueError("Invalid scanner result")
        result["unscanned_files"] = max(0, coverage["snapshot_files"] - result.get("files_scanned", 0))
        if (coverage["skipped_files"] or result["unscanned_files"]) and result["status"] == "completed":
            result["status"] = "partial"
        return {**result, **coverage, "commit": commit}
    finally:
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)


def main():
    request = pathlib.Path(sys.argv[1])
    try:
        settings = json.loads(request.read_text())
    finally:
        request.unlink(missing_ok=True)
    image = settings["image"]
    if not re.fullmatch(r"ghcr\.io/yeusepe/coolify@sha256:[0-9a-f]{64}", image):
        raise ValueError("Scanner must be pinned")
    run(["docker", "pull", image], timeout=180)
    host_keys = ""
    if any(target.get("private_key") for target in settings["targets"]):
        with urllib.request.urlopen(urllib.request.Request("https://api.github.com/meta", headers={"User-Agent": "racconify-source-scanner"}), timeout=15) as response:
            keys = json.load(response)["ssh_keys"]
        host_keys = "".join("github.com " + key + "\n" for key in keys if re.fullmatch(r"(?:ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) [A-Za-z0-9+/=]+", key))
        if not host_keys:
            raise ValueError("GitHub host keys unavailable")
    results = []
    with tempfile.TemporaryDirectory(prefix="racconify-source-") as temporary:
        os.chmod(temporary, 0o700)
        for target in settings["targets"]:
            try:
                result = scan(target, image, pathlib.Path(temporary), host_keys)
            except Exception:
                result = {"status": "failed", "error": "Repository fetch or isolated scan failed. Previous findings are retained."}
            results.append({"id": target["id"], **result})
    print(json.dumps({"repositories": results}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(json.dumps({"error": "Source scan could not start. Check Git, Python 3, Docker and repository access."}))
        sys.exit(1)
