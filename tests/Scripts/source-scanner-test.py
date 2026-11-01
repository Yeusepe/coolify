import importlib.util
import pathlib
import unittest

path = pathlib.Path(__file__).resolve().parents[2] / "docker/source-scanner/scan.py"
spec = importlib.util.spec_from_file_location("source_scanner", path)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class ScannerOutputTest(unittest.TestCase):
    def test_uses_trusted_messages_and_drops_source_and_metavariables(self):
        rule = {"rule": "safe-rule", "message": "Review eval use", "severity": "WARNING", "cwes": ["CWE-95"]}
        data = {"results": [{"check_id": "safe-rule", "path": "src/app.ts", "start": {"line": 7}, "extra": {"lines": "PRIVATE_SOURCE", "message": "PRIVATE_SECRET", "metavars": {"value": "PRIVATE_SECRET"}}}], "paths": {"scanned": ["src/app.ts"]}}
        result = scanner.normalize(data, {"safe-rule": rule})
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["findings"][0]["message"], "Review eval use")
        self.assertNotIn("PRIVATE", str(result))
        self.assertEqual(result["findings"][0]["line"], 7)

    def test_rejects_paths_outside_source_and_unknown_rules_without_claiming_clean(self):
        data = {"results": [{"check_id": "unknown", "path": "app.ts", "start": {"line": 1}}, {"check_id": "known", "path": "../secret", "start": {"line": 1}}], "paths": {"scanned": ["app.ts"]}}
        result = scanner.normalize(data, {"known": {"rule": "known"}})
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["error_count"], 2)

    def test_no_supported_files_is_not_a_clean_scan(self):
        self.assertEqual(scanner.normalize({"results": [], "paths": {"scanned": []}}, {})["status"], "partial")


if __name__ == "__main__":
    unittest.main()
