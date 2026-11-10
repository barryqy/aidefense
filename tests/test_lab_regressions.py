import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import aidefense_api
import aidefense_lab


SAFE_RESPONSE = {
    "is_safe": True,
    "classifications": [],
    "action": "Allow",
    "severity": "NONE_SEVERITY",
    "rules": [],
}
SCAN_ID = "11111111-2222-4333-8444-555555555555"
PAGING = {"total": 2, "count": 2, "limit": 100, "offset": 0}
SCAN_DETAILS = {
    "scan_status_info": {
        "scan_id": SCAN_ID,
        "status": "COMPLETED",
        "created_at": "2026-11-11T00:00:00Z",
        "completed_at": "2026-11-11T00:00:10Z",
        "type": "REPOSITORY_ANALYSIS",
        "repository": {
            "url": "https://huggingface.co/example/fictional-model",
            "version": "fixture-version",
            "files_scanned": 1,
        },
        "analysis_results": {
            "paging": PAGING,
            "items": [
                {
                    "name": "model.pkl",
                    "size": 107,
                    "status": "COMPLETED",
                    "threats": {
                        "paging": {"total": 1, "count": 1, "limit": 100, "offset": 0},
                        "items": [{
                            "technique_id": "AITech-9.3",
                            "technique_name": "Code Injection",
                            "items": [{
                                "sub_technique_id": "AITech-9.3.1",
                                "sub_technique_name": "Unsafe Imports",
                                "description": "Unsafe module import",
                                "indicators": ["posix.system"],
                                "max_severity": "CRITICAL",
                                "items": [{
                                    "id": "fixture-threat",
                                    "threat_id": "unsafe-import",
                                    "threat_type": "UNSAFE_IMPORT",
                                    "severity": "CRITICAL",
                                    "details": "posix.system REDUCE",
                                    "description": "Can execute a command",
                                }],
                            }],
                        }],
                    },
                },
                {
                    "name": "README.md",
                    "size": 42,
                    "status": "SKIPPED",
                    "reason": "Unsupported format",
                    "threats": {"items": [], "paging": {"total": 0, "count": 0, "offset": 0, "limit": 100}},
                },
            ],
        },
    }
}


class ValidationTests(unittest.TestCase):
    def api(self):
        # Session and network boundaries stay synthetic; SDK serialization is real.
        with patch.object(aidefense_api, "get_primary_key", return_value="x" * 64):
            api = aidefense_api.AIDefenseAPI()
        self.assertTrue(api.initialize_clients())
        self.assertIs(type(api.http_client), aidefense_api.PolicyHttpInspectionClient)
        return api

    def test_http_failure_cannot_report_validation_success(self):
        api = self.api()
        output = io.StringIO()

        def transport(handler, **request):
            if request["url"].endswith("/http"):
                raise RuntimeError("HTTP 400: invalid rule name: Malicious URL Detection")
            return SAFE_RESPONSE

        with patch("aidefense.request_handler.RequestHandler.request", transport), contextlib.redirect_stdout(output):
            ok = api.environment_validation()

        self.assertIs(ok, False)
        self.assertIn("HTTP client test failed", output.getvalue())
        self.assertNotIn("functionality is working correctly", output.getvalue())
        self.assertNotIn("Environment validation complete", output.getvalue())


    def test_failed_chat_validation_returns_failure_without_http_probe(self):
        api = self.api()
        urls = []

        def transport(handler, **request):
            urls.append(request["url"])
            raise RuntimeError("Connection unavailable")

        with (
            patch("aidefense.request_handler.RequestHandler.request", transport),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            ok = api.environment_validation()
        self.assertIs(ok, False)
        self.assertEqual(len(urls), 1)
        self.assertTrue(urls[0].endswith("/chat"))


    def test_validation_failure_produces_nonzero_cli_status(self):
        api = self.api()
        with (
            patch.object(aidefense_api, "AIDefenseAPI", return_value=api),
            patch.object(api, "environment_validation", return_value=False),
            patch.object(sys, "argv", ["aidefense_api.py", "--environment-validation"]),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            status = aidefense_api.main()
        self.assertEqual(status, 1)

    def test_interactive_validation_does_not_claim_success_after_http_error(self):
        with patch.object(aidefense_lab, "get_primary_key", return_value="x" * 64):
            lab = aidefense_lab.AIDefenseLab()
        self.assertTrue(lab.initialize_clients())
        output = io.StringIO()

        def transport(handler, **request):
            if request["url"].endswith("/http"):
                raise RuntimeError("HTTP 400: inspection failed")
            return SAFE_RESPONSE

        with (
            patch("aidefense.request_handler.RequestHandler.request", transport),
            patch("builtins.input", return_value=""),
            contextlib.redirect_stdout(output),
        ):
            ok = lab.environment_validation()
        self.assertIs(ok, False)
        self.assertNotIn("functionality is working correctly", output.getvalue())
        self.assertNotIn("Environment validation complete", output.getvalue())




    def test_http_validation_uses_connection_policy_without_rule_overrides(self):
        api = self.api()
        sent = []

        def transport(handler, **request):
            sent.append(request)
            if request["url"].endswith("/http") and "config" in request["json_data"]:
                raise RuntimeError("HTTP 400: SDK rule override rejected")
            return SAFE_RESPONSE

        with (
            patch("aidefense.request_handler.RequestHandler.request", transport),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            ok = api.environment_validation()

        self.assertIs(ok, True)
        http = [r for r in sent if r["url"].endswith("/http")]
        self.assertEqual(len(http), 1)
        self.assertEqual(http[0]["method"], "POST")
        self.assertNotIn("config", http[0]["json_data"])
        self.assertNotIn("policy_id", http[0]["json_data"])


    def test_explicit_http_rules_and_policy_are_not_silently_changed(self):
        from aidefense.runtime.models import InspectionConfig, Rule, RuleName

        api = self.api()
        overrides = [
            {"config": InspectionConfig(enabled_rules=[Rule(rule_name=RuleName.MALICIOUS_URL_DETECTION)])},
            {"policy_id": SCAN_ID},
        ]
        for override in overrides:
            with (
                self.subTest(override=next(iter(override))),
                patch("aidefense.request_handler.RequestHandler.request", return_value=SAFE_RESPONSE) as transport,
            ):
                api.http_client.inspect_request(
                    method="POST", url="https://api.openai.com/v1/chat/completions",
                    headers={"Content-Type": "application/json"},
                    body={"messages": [{"role": "user", "content": "Hello"}]},
                    **override,
                )
            payload = transport.call_args.kwargs["json_data"]
            if "config" in override:
                self.assertEqual(payload["config"]["enabled_rules"][0]["rule_name"], "Malicious URL Detection")
            else:
                self.assertEqual(payload["policy_id"], SCAN_ID)
                self.assertNotIn("config", payload)


    def test_interactive_http_probe_uses_the_attached_policy(self):
        with patch.object(aidefense_lab, "get_primary_key", return_value="x" * 64):
            lab = aidefense_lab.AIDefenseLab()
        self.assertTrue(lab.initialize_clients())

        def transport(handler, **request):
            if request["url"].endswith("/http") and "config" in request["json_data"]:
                raise RuntimeError("HTTP 400: SDK rule override rejected")
            return SAFE_RESPONSE

        with (
            patch("aidefense.request_handler.RequestHandler.request", transport),
            patch("builtins.input", return_value=""),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            ok = lab.environment_validation()
        self.assertIs(ok, True)


    def test_policy_http_preserves_safe_and_blocked_service_results(self):
        from aidefense.runtime.models import Action, RuleName

        api = self.api()
        blocked = {
            "is_safe": False,
            "classifications": ["SECURITY_VIOLATION"],
            "action": "Block",
            "severity": "HIGH",
            "rules": [{"rule_name": "Malicious URL Detection", "classification": "SECURITY_VIOLATION"}],
            "processed_rules": [{"rule_name": "Malicious URL Detection"}],
        }
        for payload, safe, action in [(SAFE_RESPONSE, True, Action.ALLOW), (blocked, False, Action.BLOCK)]:
            with (
                self.subTest(safe=safe),
                patch("aidefense.request_handler.RequestHandler.request", return_value=payload),
            ):
                result = api.http_client.inspect_request(
                    method="POST", url="https://api.openai.com/v1/chat/completions",
                    body={"messages": [{"role": "user", "content": "Synthetic request"}]},
                )
            self.assertIs(result.is_safe, safe)
            self.assertEqual(result.action, action)
            if not safe:
                self.assertEqual(result.rules[0].rule_name, RuleName.MALICIOUS_URL_DETECTION)
                self.assertEqual(result.processed_rules[0].rule_name, RuleName.MALICIOUS_URL_DETECTION)



class ScanReadTests(unittest.TestCase):
    def script(self, name):
        path = Path(__file__).resolve().parents[1] / (name + ".py")
        self.assertTrue(path.is_file(), f"Published scan command is missing: {name}.py")
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def run_read(self, module, argv, payload):
        sent = []
        output = io.StringIO()

        def transport(handler, **request):
            sent.append(request)
            return payload

        with (
            patch.object(module, "get_mgmt_api", return_value="test-management-key"),
            patch("aidefense.request_handler.RequestHandler.request", transport),
            patch.object(sys, "argv", argv),
            contextlib.redirect_stdout(output),
        ):
            module.main()
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["method"].value, "GET")
        return output.getvalue(), sent[0]

    def test_list_history_reads_existing_scans_with_original_pagination(self):
        module = self.script("list_scans")
        payload = {"scans": {"paging": {"total": 1, "count": 1, "limit": 10, "offset": 0}, "items": [{
            "scan_id": SCAN_ID,
            "name": "fictional-model.pkl",
            "type": "FILE_ANALYSIS",
            "status": "COMPLETED",
            "files_scanned": 1,
            "created_at": "2026-11-11T00:00:00Z",
            "issues_by_severity": {"CRITICAL": 1},
        }]}}
        output, request = self.run_read(module, ["list_scans.py"], payload)
        self.assertIn("Showing 1 of 1 scans", output)
        self.assertIn(SCAN_ID, output)
        self.assertIn("CRITICAL: 1", output)
        self.assertEqual(request["params"], {"limit": 10, "offset": 0})
        self.assertTrue(request["url"].endswith("/scans"))

    def test_get_scan_reads_existing_details_without_starting_a_scan(self):
        module = self.script("get_scan")
        output, request = self.run_read(module, ["get_scan.py", SCAN_ID], SCAN_DETAILS)
        self.assertTrue(request["url"].endswith("/scans/" + SCAN_ID))
        self.assertEqual(request["params"], {"file_limit": 100, "file_offset": 0})
        for text in [
            SCAN_ID, "fixture-version", "posix.system REDUCE", "CRITICAL",
            "Skipped files: 1", "Files with threats: 1", "Clean files: 0",
        ]:
            self.assertIn(text, output)

    def test_history_only_calls_completed_scans_clean(self):
        module = self.script("list_scans")
        for status in ["FAILED", "PENDING", "IN_PROGRESS", "CANCELED", "COMPLETED"]:
            payload = {"scans": {"paging": {"total": 1, "count": 1, "offset": 0}, "items": [{
                "scan_id": SCAN_ID, "name": "fictional-model.pkl",
                "type": "FILE_ANALYSIS", "status": status, "files_scanned": 0,
                "created_at": "2026-11-11T00:00:00Z",
                "issues_by_severity": {"CRITICAL": 0, "HIGH": 0},
            }]}}
            with self.subTest(status=status):
                output, _ = self.run_read(module, ["list_scans.py"], payload)
                self.assertIn("Status: " + status, output)
                if status == "COMPLETED":
                    self.assertIn("None - All clean!", output)
                else:
                    self.assertNotIn("All clean", output)

    def test_missing_session_fails_before_any_api_request(self):
        for name, args in [("list_scans", []), ("get_scan", [SCAN_ID])]:
            module = self.script(name)
            with (
                self.subTest(script=name),
                patch.object(module, "get_mgmt_api", return_value=None),
                patch("aidefense.request_handler.RequestHandler.request") as request,
                patch.object(sys, "argv", [name + ".py", *args]),
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaises(SystemExit) as exit_info,
            ):
                module.main()
            self.assertEqual(exit_info.exception.code, 1)
            request.assert_not_called()

    def test_failed_file_is_not_reported_as_clean(self):
        module = self.script("get_scan")
        payload = copy.deepcopy(SCAN_DETAILS)
        payload["scan_status_info"]["analysis_results"]["items"][1]["status"] = "FAILED"
        output, _ = self.run_read(module, ["get_scan.py", SCAN_ID], payload)
        self.assertIn("Clean files: 0", output)
        self.assertIn("Other files: 1", output)
        self.assertIn("Status: FAILED", output)

    def test_scan_read_api_error_has_nonzero_status(self):
        for name, args in [("list_scans", []), ("get_scan", [SCAN_ID])]:
            module = self.script(name)
            with (
                self.subTest(script=name),
                patch.object(module, "get_mgmt_api", return_value="test-management-key"),
                patch("aidefense.request_handler.RequestHandler.request", side_effect=RuntimeError("Service unavailable")),
                patch.object(sys, "argv", [name + ".py", *args]),
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaises(SystemExit) as exit_info,
            ):
                module.main()
            self.assertEqual(exit_info.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
