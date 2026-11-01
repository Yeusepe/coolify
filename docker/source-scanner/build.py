import hashlib
import io
import json
import pathlib
import re
import tarfile
import urllib.request

import yaml

RULES_COMMIT = "9c375dc49a7cd431e2b95c2620af651ef1d096a4"
LANGUAGES = {"javascript", "typescript", "csharp", "php", "python", "generic", "yaml", "dockerfile"}
OUT = pathlib.Path("/out")
OUT.mkdir()


def download(url, expected):
    with urllib.request.urlopen(url, timeout=60) as response:
        content = response.read()
    if hashlib.sha256(content).hexdigest() != expected:
        raise ValueError("Scanner dependency checksum mismatch")
    return content


binary = download(
    "https://github.com/opengrep/opengrep/releases/download/v1.33.1/opengrep_manylinux_x86",
    "46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808",
)
(OUT / "opengrep").write_bytes(binary)
(OUT / "opengrep").chmod(0o755)
archive = download(
    f"https://gitlab.com/gitlab-org/security-products/sast-rules/-/archive/{RULES_COMMIT}/sast-rules-{RULES_COMMIT}.tar.gz",
    "2a2411439e46e589fb9ba973c02f52061732d45e85e16082cffe9c4e19ad9652",
)
rules, index = [], {}
with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
    for entry in sorted(bundle.getmembers(), key=lambda item: item.name):
        path = pathlib.PurePosixPath(entry.name)
        if path.name == "LICENSE" and len(path.parts) == 2:
            (OUT / "GITLAB-LICENSE").write_bytes(bundle.extractfile(entry).read())
        if not entry.isfile() or len(path.parts) < 3 or path.parts[1] not in LANGUAGES or path.suffix not in {".yml", ".yaml"}:
            continue
        data = yaml.safe_load(bundle.extractfile(entry))
        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            continue
        for original in data["rules"]:
            rule = dict(original)
            if not set(rule.get("languages", [])) <= LANGUAGES:
                continue
            identifier = "gitlab." + re.sub(r"[^A-Za-z0-9_.-]", ".", "/".join(path.parts[1:])) + "." + rule["id"]
            if identifier in index:
                raise ValueError("Duplicate scanner rule")
            rule["id"] = identifier
            rules.append(rule)
            metadata = json.dumps(rule.get("metadata", {}))
            index[identifier] = {
                "rule": identifier,
                "message": str(rule.get("message", "Review this source pattern."))[:2000],
                "severity": rule.get("severity", "INFO"),
                "cwes": sorted(set(re.findall(r"CWE-[1-9][0-9]{0,5}", metadata))),
                "rule_url": f"https://gitlab.com/gitlab-org/security-products/sast-rules/-/blob/{RULES_COMMIT}/" + "/".join(path.parts[1:]),
            }
if len(rules) < 100:
    raise ValueError("Expected language rule coverage was not built")
(OUT / "rules.json").write_text(json.dumps({"rules": rules}, sort_keys=True), encoding="utf-8")
(OUT / "index.json").write_text(json.dumps(index, sort_keys=True), encoding="utf-8")
(OUT / "manifest.json").write_text(json.dumps({"engine": "Opengrep 1.33.1", "rules_commit": RULES_COMMIT, "rule_count": len(rules), "languages": sorted(LANGUAGES), "format": 1}), encoding="utf-8")
with urllib.request.urlopen("https://raw.githubusercontent.com/opengrep/opengrep/092c80f/LICENSE", timeout=30) as response:
    (OUT / "OPENGREP-LICENSE").write_bytes(response.read())
