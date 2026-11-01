import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path("/opt/scanner")


def safe_path(value):
    if not isinstance(value, str) or len(value) > 600 or any(ord(character) < 32 for character in value):
        return None
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        return None
    return str(path)


def normalize(data, index):
    findings, invalid = [], 0
    seen = set()
    for match in data.get("results", []):
        rule = index.get(match.get("check_id"))
        path = safe_path(match.get("path"))
        line = match.get("start", {}).get("line")
        if not rule or not path or not isinstance(line, int) or not 0 < line < 10000000:
            invalid += 1
            continue
        fingerprint = hashlib.sha256(f"{rule['rule']}|{path}|{line}".encode()).hexdigest()
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        if len(findings) < 1000:
            findings.append({**rule, "path": path, "line": line, "fingerprint": fingerprint})
    findings.sort(key=lambda finding: (finding["path"], finding["line"], finding["rule"]))
    errors = len(data.get("errors", [])) + invalid
    scanned = len(data.get("paths", {}).get("scanned", []))
    return {"findings": findings, "finding_count": len(seen), "truncated": len(seen) > len(findings), "error_count": errors, "files_scanned": scanned, "status": "partial" if errors or not scanned else "completed"}


def main():
    manifest = json.loads((ROOT / "manifest.json").read_text())
    if sys.argv[1:] == ["--manifest"]:
        print(json.dumps(manifest))
        return
    index = json.loads((ROOT / "index.json").read_text())
    with tempfile.TemporaryDirectory(prefix="source-scan-") as temporary:
        output = pathlib.Path(temporary) / "scan.json"
        command = [str(ROOT / "opengrep"), "scan", "--config", str(ROOT / "rules.json"), "--json-output", str(output), "--no-rewrite-rule-ids", "--metrics", "off", "--disable-version-check", "--disable-nosem", "--no-git-ignore", "--taint-intrafile", "--jobs", "2", "--timeout", "5", "--timeout-threshold", "3", "--max-memory", "1000", "--max-target-bytes", "1000000", "."]
        try:
            process = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
            if not output.is_file() or output.stat().st_size > 32000000:
                raise ValueError("Scanner output is unavailable or too large")
            data = json.loads(output.read_text(encoding="utf-8"))
            result = normalize(data, index)
            if process.returncode not in {0, 1}:
                result["status"] = "partial"
                result["error_count"] += 1
            print(json.dumps({**manifest, **result}))
        except (subprocess.TimeoutExpired, ValueError, OSError, TypeError, KeyError):
            print(json.dumps({**manifest, "status": "failed", "error": "The isolated scanner did not complete. Previous findings remain available."}))


if __name__ == "__main__":
    main()
