import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import napalm_client as client


def profile(driver="eos", **updates):
    value = {
        "driver": driver,
        "hostname": "edge01.example.invalid",
        "username": "automation",
        "password": "device-password",
        "timeout_seconds": 30,
    }
    if driver in client.SSH_DRIVERS:
        value["known_hosts"] = "edge01.example.invalid ssh-ed25519 AAAATEST\n"
    value.update(updates)
    return value


class FakeDriver:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.calls = []
        self.diff = "interface Ethernet1\n password exposed\n description safe\n"
        self.pending = False
        self.fail_load = False
        self.fact_value = {"hostname": "edge01"}

    def open(self):
        self.calls.append(("open",))

    def close(self):
        self.calls.append(("close",))

    def get_facts(self):
        self.calls.append(("get_facts",))
        return self.fact_value

    def get_interfaces(self):
        return {"Ethernet1": {"is_up": True}}

    def get_interfaces_counters(self):
        return {"Ethernet1": {"rx_errors": 0}}

    def get_environment(self):
        return {"memory": {"used_ram": 1}}

    def get_bgp_neighbors(self):
        return {"global": {"peers": {}}}

    def get_bgp_config(self, **kwargs):
        self.calls.append(("get_bgp_config", kwargs))
        return {"PEERS": {"neighbors": {"192.0.2.1": {"authentication_key": "bgp-secret"}}}}

    def get_route_to(self, **kwargs):
        self.calls.append(("get_route_to", kwargs))
        return {kwargs["destination"]: []}

    def get_optics(self):
        return {}

    def get_ntp_servers(self):
        return {"192.0.2.123": {}}

    def get_ntp_peers(self):
        return {}

    def get_ntp_stats(self):
        return []

    def get_config(self, **kwargs):
        self.calls.append(("get_config", kwargs))
        return {"running": "hostname edge01\nenable secret leaked\n", "candidate": "", "startup": ""}

    def load_merge_candidate(self, **kwargs):
        self.calls.append(("load_merge_candidate", kwargs))
        if self.fail_load:
            raise RuntimeError("load response contained device-password")

    def load_replace_candidate(self, **kwargs):
        self.calls.append(("load_replace_candidate", kwargs))
        if self.fail_load:
            raise RuntimeError("load response contained device-password")

    def compare_config(self):
        self.calls.append(("compare_config",))
        return self.diff

    def discard_config(self):
        self.calls.append(("discard_config",))

    def commit_config(self, **kwargs):
        self.calls.append(("commit_config", kwargs))
        self.pending = kwargs.get("revert_in") is not None

    def has_pending_commit(self):
        self.calls.append(("has_pending_commit",))
        return self.pending

    def confirm_commit(self):
        self.calls.append(("confirm_commit",))
        self.pending = False

    def rollback(self):
        self.calls.append(("rollback",))

    def ping(self, **kwargs):
        self.calls.append(("ping", kwargs))
        return {"success": {"probes_sent": kwargs["count"]}}

    def traceroute(self, **kwargs):
        self.calls.append(("traceroute", kwargs))
        return {"success": {}}


class Factory:
    def __init__(self, device=None):
        self.device = device or FakeDriver()
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        self.device.kwargs = kwargs
        return self.device


class MetadataContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actions = {
            path.stem: path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "actions").glob("*.yaml"))
        }

    def test_expected_actions_exist(self):
        self.assertEqual(
            {
                "get_facts", "get_interfaces", "get_interfaces_counters", "get_environment",
                "get_bgp_neighbors", "get_bgp_config", "get_route_to", "get_optics",
                "get_ntp", "get_config", "compare_config", "load_merge", "load_replace",
                "commit_config", "confirm_commit", "discard_config", "rollback", "ping",
                "traceroute",
            },
            set(self.actions),
        )

    def test_all_actions_use_flat_stdin_and_key_profiles(self):
        for name, text in self.actions.items():
            with self.subTest(action=name):
                for required in (
                    f"ref: napalm.{name}", "runner_type: python", 'runtime_version: ">=3.10"',
                    "entry_point: napalm_action.py", "parameter_delivery: stdin",
                    "parameter_format: json", "output_format: json",
                    "default_execution_permission_set_refs: [standard]",
                    'default: "napalm.credentials"', "operation: {type: string, required: true}",
                    "result: {type: object, required: true}",
                ):
                    self.assertIn(required, text)
                for forbidden in ("  password:", "  username:", "  ssh_private_key:", "  optional_args:"):
                    self.assertNotIn(forbidden, text)

    def test_mutations_and_read_only_actions_are_explicit(self):
        for name in ("commit_config", "confirm_commit", "discard_config", "rollback"):
            self.assertIn("Mutating", self.actions[name])
            self.assertIn("const: true, required: true", self.actions[name])
        for name in ("get_facts", "get_interfaces", "get_config", "ping", "traceroute"):
            self.assertIn("Read Only", self.actions[name])
        for name in ("compare_config", "load_merge", "load_replace"):
            self.assertIn("discard", self.actions[name].lower())
            self.assertNotIn("read-only", self.actions[name].lower())
        self.assertIn("confirm_replace", self.actions["load_replace"])
        self.assertIn("confirm_replace", self.actions["commit_config"])

    def test_provenance_license_and_deferred_sensor_are_documented(self):
        source = json.loads((ROOT / "SOURCE.json").read_text(encoding="utf-8"))
        self.assertEqual("8af575b481a28f3a284bbb4cf7073cf72684f1d4", source["upstream"]["revision"])
        self.assertEqual("1.1.0", source["upstream"]["version"])
        self.assertEqual("deafa21d1c86158d03a8e456a5fd4c9165bfb10e", source["api_reference"]["revision"])
        self.assertEqual("5.2.0", source["api_reference"]["version"])
        self.assertEqual("b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1", hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest())
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for name in self.actions:
            self.assertIn(f"`napalm.{name}`", readme)
        for phrase in ("explicitly deferred", "configuration-loss", "connection-bound", "commit-confirm", "per-driver"):
            self.assertIn(phrase, readme)
        self.assertFalse((ROOT / "sensors").exists())
        self.assertFalse((ROOT / "rules").exists())

    def test_dependencies_are_declared_and_pinned(self):
        requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("napalm==5.2.0", requirements)
        self.assertIn("attune-sdk", requirements)
        self.assertNotIn("pytest", requirements)


class ValidationTests(unittest.TestCase):
    def test_profiles_require_curated_driver_auth_and_host_verification(self):
        valid = client.validate_profile(profile("ios"))
        self.assertEqual("ios", valid["driver"])
        invalid = [
            profile(driver="mock"),
            {**profile("ios"), "known_hosts": ""},
            {**profile(), "password": "", "ssh_private_key": None},
            {**profile(), "ssh_private_key": "KEY"},
            {**profile(), "extra": "value"},
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(client.NapalmPackError):
                client.validate_profile(value)

    def test_optional_args_are_driver_specific_and_safe(self):
        accepted = client.validate_profile(profile("ios", optional_args={"transport": "ssh", "port": 2222, "inline_transfer": True, "global_delay_factor": 2}))
        self.assertEqual(2222, accepted["optional_args"]["port"])
        invalid = [
            profile("ios", optional_args={"key_file": "/tmp/key"}),
            profile("ios", optional_args={"transport": "telnet"}),
            profile("ios", optional_args={"auto_rollback_on_error": False}),
            profile("eos", optional_args={"lock_disable": True}),
            profile("nxos", optional_args={"ssl_verify": False}),
            profile("junos", optional_args={"port": "22"}),
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(client.NapalmPackError):
                client.validate_profile(value)

    def test_probe_and_filter_inputs_reject_command_injection(self):
        device = FakeDriver()
        validated = client.validate_profile(profile())
        for operation, params in (
            ("ping", {"destination": "8.8.8.8; reload"}),
            ("ping", {"destination": "8.8.8.8", "vrf": "blue | show run"}),
            ("get_route_to", {"destination": "0.0.0.0/0;show"}),
            ("get_bgp_config", {"neighbor": "192.0.2.1;reload"}),
        ):
            with self.subTest(operation=operation), self.assertRaises(client.NapalmPackError):
                client._execute_device(operation, params, validated, device)

    def test_unknown_action_parameters_are_rejected_before_connect(self):
        factory = Factory()
        with self.assertRaisesRegex(client.NapalmPackError, "unsupported fields"):
            client.execute_with_profile("get_facts", {"optional_args": {"secret": "x"}}, profile(), factory)
        self.assertEqual([], factory.calls)


class ClientLifecycleTests(unittest.TestCase):
    def test_read_only_getter_opens_closes_and_returns_structured_data(self):
        device, factory = FakeDriver(), Factory()
        factory.device = device
        result = client.execute_with_profile("get_facts", {}, profile(), factory)
        self.assertEqual({"driver": "eos", "data": {"hostname": "edge01"}}, result)
        self.assertEqual("https", factory.calls[0]["optional_args"]["transport"])
        self.assertTrue(factory.calls[0]["optional_args"]["enforce_verification"])
        self.assertEqual([("open",), ("get_facts",), ("close",)], device.calls)

    def test_ssh_key_and_known_hosts_are_private_temporary_files(self):
        observed = {}

        def factory(**kwargs):
            optional = kwargs["optional_args"]
            for name in ("key_file", "alt_key_file"):
                path = Path(optional[name])
                observed[name] = path
                observed[f"{name}_mode"] = stat.S_IMODE(path.stat().st_mode)
                observed[f"{name}_text"] = path.read_text(encoding="utf-8")
            self.assertTrue(optional["ssh_strict"])
            self.assertFalse(optional["allow_agent"])
            self.assertFalse(optional["use_keys"])
            return FakeDriver(**kwargs)

        key_profile = profile("ios", password=None, ssh_private_key="-----BEGIN PRIVATE KEY-----\nPRIVATE\n-----END PRIVATE KEY-----\n")
        result = client.execute_with_profile("get_facts", {}, key_profile, factory)
        self.assertEqual(0o600, observed["key_file_mode"])
        self.assertEqual(0o600, observed["alt_key_file_mode"])
        self.assertIn("PRIVATE", observed["key_file_text"])
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertFalse(observed["key_file"].exists())
        self.assertFalse(observed["alt_key_file"].exists())

    def test_bgp_and_configuration_outputs_are_redacted(self):
        device = FakeDriver()
        bgp = client.execute_with_profile("get_bgp_config", {}, profile(), Factory(device))
        self.assertEqual("[REDACTED]", bgp["data"]["PEERS"]["neighbors"]["192.0.2.1"]["authentication_key"])
        config = client.execute_with_profile("get_config", {}, profile(), Factory(device))
        self.assertNotIn("leaked", json.dumps(config))
        self.assertIn("[REDACTED CONFIG LINE]", config["data"]["running"])
        call = next(item for item in device.calls if item[0] == "get_config")
        self.assertEqual({"retrieve": "all", "full": False, "sanitized": True, "format": "text"}, call[1])

    def test_preview_always_discards_and_redacts_diff(self):
        device = FakeDriver()
        result = client.execute_with_profile("load_merge", {"config": "interface Ethernet1\n"}, profile(), Factory(device))
        self.assertTrue(result["changed"])
        self.assertTrue(result["candidate_discarded"])
        self.assertNotIn("exposed", result["diff"])
        self.assertEqual(1, sum(call[0] == "discard_config" for call in device.calls))
        self.assertLess(device.calls.index(("discard_config",)), device.calls.index(("close",)))

    def test_partial_load_failure_still_attempts_discard_and_hides_exception(self):
        device = FakeDriver()
        device.fail_load = True
        with self.assertRaises(client.NapalmPackError) as caught:
            client.execute_with_profile("load_merge", {"config": "bad"}, profile(), Factory(device))
        self.assertIn(("discard_config",), device.calls)
        self.assertNotIn("device-password", str(caught.exception))

    def test_commit_is_one_connection_confirmed_and_noop_safe(self):
        device = FakeDriver()
        result = client.execute_with_profile("commit_config", {"config": "interface Ethernet1", "confirm": True, "message": "change 42"}, profile(), Factory(device))
        self.assertTrue(result["committed"])
        commit = next(call for call in device.calls if call[0] == "commit_config")
        self.assertEqual({"message": "change 42", "revert_in": None}, commit[1])
        self.assertNotIn(("discard_config",), device.calls)

        noop = FakeDriver()
        noop.diff = ""
        result = client.execute_with_profile("commit_config", {"config": "interface Ethernet1", "confirm": True}, profile(), Factory(noop))
        self.assertFalse(result["changed"])
        self.assertIn(("discard_config",), noop.calls)
        self.assertFalse(any(call[0] == "commit_config" for call in noop.calls))

    def test_replace_and_commit_confirm_require_explicit_acknowledgement(self):
        for operation, params in (
            ("load_replace", {"config": "complete"}),
            ("commit_config", {"config": "complete", "mode": "replace", "confirm": True}),
            ("commit_config", {"config": "merge"}),
        ):
            factory = Factory()
            with self.subTest(operation=operation), self.assertRaises(client.NapalmPackError):
                client.execute_with_profile(operation, params, profile(), factory)
            self.assertEqual([], factory.calls)
        with self.assertRaisesRegex(client.NapalmPackError, "not supported"):
            client.execute_with_profile("commit_config", {"config": "x", "confirm": True, "revert_in": 60}, profile("nxos"), Factory())

        device = FakeDriver()
        result = client.execute_with_profile("commit_config", {"config": "x", "confirm": True, "revert_in": 120}, profile(), Factory(device))
        self.assertTrue(result["pending_commit"])

    def test_confirm_discard_and_rollback_contracts(self):
        pending = FakeDriver()
        pending.pending = True
        result = client.execute_with_profile("confirm_commit", {"confirm": True}, profile(), Factory(pending))
        self.assertTrue(result["confirmed"])
        for operation, expected in (("discard_config", "discarded"), ("rollback", "rolled_back")):
            device = FakeDriver()
            result = client.execute_with_profile(operation, {"confirm": True}, profile(), Factory(device))
            self.assertTrue(result[expected])
            with self.assertRaises(client.NapalmPackError):
                client.execute_with_profile(operation, {}, profile(), Factory())

    def test_support_matrix_rejects_before_connection(self):
        factory = Factory()
        with self.assertRaisesRegex(client.NapalmPackError, "not supported"):
            client.execute_with_profile("get_ntp", {"resource": "stats"}, profile("nxos_ssh"), factory)
        self.assertEqual([], factory.calls)

    def test_ping_is_bounded_and_passed_as_typed_keywords(self):
        device = FakeDriver()
        result = client.execute_with_profile("ping", {"destination": "192.0.2.1", "count": 20, "ttl": 64, "vrf": "blue"}, profile(), Factory(device))
        self.assertEqual(20, result["data"]["success"]["probes_sent"])
        kwargs = next(call[1] for call in device.calls if call[0] == "ping")
        self.assertEqual("192.0.2.1", kwargs["destination"])
        with self.assertRaises(client.NapalmPackError):
            client.execute_with_profile("ping", {"destination": "192.0.2.1", "count": 21}, profile(), Factory())

    def test_output_limit_and_remote_errors_do_not_leak(self):
        device = FakeDriver()
        device.fact_value = {"blob": "x" * 70000}
        with self.assertRaisesRegex(client.NapalmPackError, "max_output_bytes"):
            client.execute_with_profile("get_facts", {}, profile(max_output_bytes=65536), Factory(device))
        failing = FakeDriver()
        failing.get_facts = mock.Mock(side_effect=RuntimeError("device-password private-key"))
        with self.assertRaises(client.NapalmPackError) as caught:
            client.execute_with_profile("get_facts", {}, profile(), Factory(failing))
        self.assertNotIn("device-password", str(caught.exception))
        self.assertNotIn("private-key", str(caught.exception))


class EntryPointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("napalm_action_test", ROOT / "actions" / "napalm_action.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def run_main(self, stdin, action="napalm.get_facts"):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"ATTUNE_ACTION": action}, clear=False), mock.patch("sys.stdin", io.StringIO(stdin)), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            code = self.module.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_success_and_input_contract(self):
        with mock.patch.object(self.module, "execute_action", return_value={"driver": "eos", "data": {}}):
            code, stdout, stderr = self.run_main("{}")
        self.assertEqual(0, code)
        self.assertEqual({"operation": "get_facts", "result": {"driver": "eos", "data": {}}}, json.loads(stdout))
        self.assertEqual("", stderr)
        code, stdout, stderr = self.run_main("[]")
        self.assertEqual(1, code)
        self.assertIn("JSON object", stderr)
        code, stdout, stderr = self.run_main('{"bad":')
        self.assertEqual(1, code)
        self.assertIn("invalid stdin JSON", stderr)

    def test_unexpected_error_text_is_not_returned(self):
        with mock.patch.object(self.module, "execute_action", side_effect=RuntimeError("device-password")):
            code, stdout, stderr = self.run_main("{}")
        self.assertEqual(1, code)
        self.assertEqual("", stdout)
        self.assertNotIn("device-password", stderr)


if __name__ == "__main__":
    unittest.main()
