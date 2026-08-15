"""Validated NAPALM client, connection lifecycle, and action dispatch."""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any


class NapalmPackError(RuntimeError):
    """Safe operator-facing error without device or credential details."""


DRIVERS = {"eos", "ios", "iosxr", "iosxr_netconf", "junos", "nxos", "nxos_ssh"}
CONFIG_DRIVERS = DRIVERS - {"nxos_ssh"}
SSH_DRIVERS = {"ios", "iosxr", "iosxr_netconf", "junos", "nxos_ssh"}
KEY_DRIVERS = SSH_DRIVERS
COMMIT_CONFIRM_DRIVERS = {"eos", "ios", "junos"}
SUPPORT = {
    "get_facts": DRIVERS,
    "get_interfaces": DRIVERS,
    "get_interfaces_counters": DRIVERS - {"nxos"},
    "get_environment": DRIVERS,
    "get_bgp_neighbors": DRIVERS,
    "get_bgp_config": DRIVERS - {"nxos", "nxos_ssh"},
    "get_route_to": {"eos"},
    "get_optics": {"eos", "ios", "junos", "nxos_ssh"},
    "get_ntp_peers": DRIVERS - {"eos"},
    "get_ntp_servers": DRIVERS,
    "get_ntp_stats": DRIVERS - {"nxos_ssh"},
    "get_config": DRIVERS - {"iosxr_netconf"},
    "ping": {"eos", "ios", "junos", "nxos", "nxos_ssh"},
    "traceroute": DRIVERS,
    "configuration": CONFIG_DRIVERS,
}

_PROFILE_FIELDS = {
    "driver", "hostname", "username", "password", "ssh_private_key", "known_hosts",
    "enable_password", "timeout_seconds", "max_output_bytes", "ca_bundle", "optional_args",
}
_OPTIONAL_FIELDS = {
    "eos": {"transport", "port", "lock_disable"},
    "ios": {"transport", "port", "inline_transfer", "auto_rollback_on_error", "auto_file_prompt", "canonical_int", "global_delay_factor"},
    "iosxr": {"port", "config_lock", "keepalive", "global_delay_factor"},
    "iosxr_netconf": {"port", "config_lock", "config_encoding"},
    "junos": {"port", "config_lock", "keepalive", "auto_probe", "huge_tree"},
    "nxos": {"transport", "port"},
    "nxos_ssh": {"port", "global_delay_factor"},
}
_SENSITIVE_KEYS = re.compile(r"(?:password|passwd|secret|token|private.?key|authentication.?key|community|passphrase)", re.I)
_SENSITIVE_LINE = re.compile(r"\b(?:password|passwd|secret|community|authentication-key|pre-shared-key|private-key|snmp-server)\b", re.I)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:/@-]{1,255}$")
_HOST = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)$")
_MAX_CONFIG_BYTES = 2 * 1024 * 1024
_ACTION_FIELDS = {
    "get_facts": set(), "get_interfaces": set(), "get_interfaces_counters": set(),
    "get_environment": set(), "get_bgp_neighbors": set(), "get_optics": set(),
    "get_bgp_config": {"group", "neighbor"},
    "get_route_to": {"destination", "protocol", "longer"},
    "get_ntp": {"resource"}, "get_config": {"retrieve", "full"},
    "compare_config": {"config", "mode", "confirm_replace"},
    "load_merge": {"config"}, "load_replace": {"config", "confirm_replace"},
    "commit_config": {"config", "mode", "confirm", "confirm_replace", "message", "revert_in"},
    "confirm_commit": {"confirm"}, "discard_config": {"confirm"}, "rollback": {"confirm"},
    "ping": {"destination", "source", "ttl", "probe_timeout", "vrf", "size", "count", "source_interface"},
    "traceroute": {"destination", "source", "ttl", "probe_timeout", "vrf"},
}


def _fetch_key(ref: Any) -> dict[str, Any]:
    if not isinstance(ref, str) or not ref.strip() or len(ref) > 255:
        raise NapalmPackError("credential_key must be a non-empty string")
    try:
        import attune
        from attune.api_client.api.secrets import get_key
    except ImportError as exc:
        raise NapalmPackError("attune-sdk is required to resolve credential_key") from exc
    try:
        response = get_key.sync_detailed(ref, client=attune.context.client, decrypt=True)
    except Exception as exc:
        raise NapalmPackError("unable to read the credential Key") from exc
    status = int(response.status_code)
    if status == 404:
        raise NapalmPackError("credential Key was not found")
    if status >= 400 or not response.parsed:
        raise NapalmPackError(f"credential Key lookup failed with status {status}")
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise NapalmPackError("credential Key must contain a JSON object") from exc
    if not isinstance(value, dict):
        raise NapalmPackError("credential Key must contain an object")
    return value


def _text(value: Any, name: str, maximum: int = 255) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value or "\n" in value or "\r" in value:
        raise NapalmPackError(f"{name} must be a non-empty single-line string of at most {maximum} characters")
    return value


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise NapalmPackError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise NapalmPackError(f"{name} must be a boolean")
    return value


def _validate_optional(driver: str, value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise NapalmPackError("optional_args must be an object")
    unexpected = set(value) - _OPTIONAL_FIELDS[driver]
    if unexpected:
        raise NapalmPackError(f"optional_args contains unsupported fields for driver {driver}")
    result: dict[str, Any] = {}
    for name, item in value.items():
        if name == "port":
            result[name] = _integer(item, "optional_args.port", 1, 65535)
        elif name in {"keepalive", "auto_probe"}:
            result[name] = _integer(item, f"optional_args.{name}", 0, 300)
        elif name == "global_delay_factor":
            if isinstance(item, bool) or not isinstance(item, (int, float)) or not math.isfinite(float(item)) or not 0.1 <= float(item) <= 10:
                raise NapalmPackError("optional_args.global_delay_factor must be between 0.1 and 10")
            result[name] = float(item)
        elif name == "transport":
            expected = "ssh" if driver == "ios" else "https"
            if item != expected:
                raise NapalmPackError(f"optional_args.transport for {driver} must be {expected!r}")
            result[name] = item
        elif name == "config_encoding":
            if item not in {"cli", "xml"}:
                raise NapalmPackError("optional_args.config_encoding must be 'cli' or 'xml'")
            result[name] = item
        else:
            result[name] = _boolean(item, f"optional_args.{name}")
    if result.get("auto_rollback_on_error") is False:
        raise NapalmPackError("optional_args.auto_rollback_on_error cannot be disabled")
    if result.get("lock_disable") is True:
        raise NapalmPackError("optional_args.lock_disable cannot be enabled")
    return result


def validate_profile(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise NapalmPackError("credential Key must contain an object")
    unexpected = set(value) - _PROFILE_FIELDS
    if unexpected:
        raise NapalmPackError("credential Key contains unsupported fields")
    driver = value.get("driver")
    if driver not in DRIVERS:
        raise NapalmPackError(f"driver must be one of {', '.join(sorted(DRIVERS))}")
    hostname = _text(value.get("hostname"), "hostname")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if not _HOST.fullmatch(hostname):
            raise NapalmPackError("hostname must be a valid IP address or DNS hostname")
    username = _text(value.get("username"), "username", 128)
    password = value.get("password")
    private_key = value.get("ssh_private_key")
    if password is not None and (not isinstance(password, str) or len(password) > 4096 or "\x00" in password):
        raise NapalmPackError("password in the credential Key is invalid")
    if private_key is not None and (not isinstance(private_key, str) or not private_key.strip() or len(private_key.encode()) > 128 * 1024 or "\x00" in private_key):
        raise NapalmPackError("ssh_private_key in the credential Key is invalid")
    if bool(password) == bool(private_key):
        raise NapalmPackError("credential Key requires exactly one of password or ssh_private_key")
    if private_key and driver not in KEY_DRIVERS:
        raise NapalmPackError(f"driver {driver} does not support pack-managed SSH private keys")
    known_hosts = value.get("known_hosts")
    if driver in SSH_DRIVERS:
        if not isinstance(known_hosts, str) or not known_hosts.strip() or len(known_hosts.encode()) > 1024 * 1024:
            raise NapalmPackError("SSH driver profiles require non-empty known_hosts data")
    elif known_hosts is not None:
        raise NapalmPackError("known_hosts is only valid for SSH driver profiles")
    enable_password = value.get("enable_password")
    if enable_password is not None and (driver not in {"eos", "ios", "nxos_ssh"} or not isinstance(enable_password, str) or not enable_password or len(enable_password) > 4096 or "\x00" in enable_password):
        raise NapalmPackError("enable_password is invalid for this driver")
    timeout = _integer(value.get("timeout_seconds", 60), "timeout_seconds", 5, 300)
    max_output = _integer(value.get("max_output_bytes", 2 * 1024 * 1024), "max_output_bytes", 65536, 10 * 1024 * 1024)
    ca_bundle = value.get("ca_bundle")
    if ca_bundle is not None:
        if driver != "nxos" or not isinstance(ca_bundle, str) or not os.path.isabs(ca_bundle) or len(ca_bundle) > 4096 or "\x00" in ca_bundle or "\n" in ca_bundle or "\r" in ca_bundle:
            raise NapalmPackError("ca_bundle must be an absolute path for the nxos HTTPS driver")
    return {
        "driver": driver,
        "hostname": hostname,
        "username": username,
        "password": password or "",
        "ssh_private_key": private_key,
        "known_hosts": known_hosts,
        "enable_password": enable_password,
        "timeout": timeout,
        "max_output": max_output,
        "ca_bundle": ca_bundle,
        "optional_args": _validate_optional(driver, value.get("optional_args")),
    }


def _write_private(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
        handle.write(content)


def _ssh_config_path(path: Path) -> str:
    value = str(path)
    if "\n" in value or "\r" in value or "\x00" in value:
        raise NapalmPackError("temporary SSH path is invalid")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class DriverSession:
    """Open one NAPALM connection and destroy temporary authentication files."""

    def __init__(self, profile: Mapping[str, Any], driver_factory: Any = None):
        self.profile = profile
        self.driver_factory = driver_factory
        self.temp: tempfile.TemporaryDirectory[str] | None = None
        self.device: Any = None

    def __enter__(self) -> Any:
        get_network_driver = None
        if self.driver_factory is None:
            try:
                from napalm import get_network_driver
            except ImportError as exc:
                raise NapalmPackError("napalm 5.2.0 is required") from exc
        optional = dict(self.profile["optional_args"])
        driver = self.profile["driver"]
        if driver == "eos":
            optional.setdefault("transport", "https")
            optional["enforce_verification"] = True
        elif driver == "nxos":
            optional.setdefault("transport", "https")
            optional["ssl_verify"] = self.profile["ca_bundle"] or True
        if self.profile["enable_password"]:
            optional["enable_password" if driver == "eos" else "secret"] = self.profile["enable_password"]
        if driver in SSH_DRIVERS:
            self.temp = tempfile.TemporaryDirectory(prefix="attune-napalm-")
            root = Path(self.temp.name)
            known_hosts = root / "known_hosts"
            _write_private(known_hosts, self.profile["known_hosts"])
            if driver in {"ios", "iosxr", "nxos_ssh"}:
                optional.update({"allow_agent": False, "use_keys": False, "ssh_strict": True, "alt_host_keys": True, "alt_key_file": str(known_hosts)})
            else:
                ssh_config = root / "ssh_config"
                _write_private(ssh_config, f"Host *\n  StrictHostKeyChecking yes\n  UserKnownHostsFile {_ssh_config_path(known_hosts)}\n  IdentitiesOnly yes\n")
                optional["ssh_config_file"] = str(ssh_config)
            if self.profile["ssh_private_key"]:
                key_file = root / "identity"
                _write_private(key_file, self.profile["ssh_private_key"])
                optional["key_file"] = str(key_file)
        factory = self.driver_factory or get_network_driver(driver)
        try:
            self.device = factory(
                hostname=self.profile["hostname"], username=self.profile["username"],
                password=self.profile["password"], timeout=self.profile["timeout"], optional_args=optional,
            )
            self.device.open()
            return self.device
        except Exception:
            self.close(ignore_errors=True)
            raise

    def close(self, *, ignore_errors: bool = False) -> None:
        error = None
        if self.device is not None:
            try:
                self.device.close()
            except Exception as exc:  # noqa: BLE001
                error = exc
            self.device = None
        if self.temp is not None:
            self.temp.cleanup()
            self.temp = None
        if error is not None and not ignore_errors:
            raise NapalmPackError("device connection cleanup failed") from error

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close(ignore_errors=exc_type is not None)


def _identifier(value: Any, name: str, *, optional: bool = False) -> str:
    if optional and (value is None or value == ""):
        return ""
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise NapalmPackError(f"{name} contains unsupported characters")
    return value


def _destination(value: Any, name: str = "destination") -> str:
    value = _text(value, name)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not _HOST.fullmatch(value):
            raise NapalmPackError(f"{name} must be an IP address or DNS hostname")
        return value


def _config(params: Mapping[str, Any]) -> str:
    value = params.get("config")
    if not isinstance(value, str) or not value.strip():
        raise NapalmPackError("config must be a non-empty string")
    if "\x00" in value or len(value.encode("utf-8")) > _MAX_CONFIG_BYTES:
        raise NapalmPackError("config exceeds the 2 MiB safety limit or contains NUL")
    return value


def _sanitize_text(value: str) -> str:
    output = []
    private_block = False
    for line in value.splitlines(keepends=True):
        upper = line.upper()
        if "BEGIN " in upper and "PRIVATE KEY" in upper:
            private_block = True
        if private_block or _SENSITIVE_LINE.search(line):
            ending = "\n" if line.endswith("\n") else ""
            output.append("[REDACTED CONFIG LINE]" + ending)
        else:
            output.append(line)
        if "END " in upper and "PRIVATE KEY" in upper:
            private_block = False
    return "".join(output)


def sanitize(value: Any, key: str = "") -> Any:
    if _SENSITIVE_KEYS.search(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(item_key): sanitize(item, str(item_key)) for item_key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(item) for item in value]
    if isinstance(value, str) and key in {"running", "candidate", "startup", "diff"}:
        return _sanitize_text(value)
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise NapalmPackError("driver returned a non-JSON-compatible value")


def _supported(driver: str, capability: str) -> None:
    if driver not in SUPPORT[capability]:
        raise NapalmPackError(f"operation is not supported by the documented {driver} driver")


def _preview(device: Any, mode: str, config: str) -> dict[str, Any]:
    attempted = False
    try:
        attempted = True
        getattr(device, f"load_{mode}_candidate")(config=config)
        diff = device.compare_config()
        if not isinstance(diff, str):
            raise NapalmPackError("driver returned an invalid configuration diff")
        return {"changed": bool(diff.strip()), "mode": mode, "diff": diff, "candidate_discarded": True}
    finally:
        if attempted:
            device.discard_config()


def _preflight_support(operation: str, params: Mapping[str, Any], driver: str) -> None:
    if operation in {"get_facts", "get_interfaces", "get_interfaces_counters", "get_environment", "get_bgp_neighbors", "get_bgp_config", "get_route_to", "get_optics", "get_config", "ping", "traceroute"}:
        _supported(driver, operation)
    elif operation == "get_ntp":
        resource = params.get("resource", "stats")
        if resource not in {"peers", "servers", "stats"}:
            raise NapalmPackError("resource must be peers, servers, or stats")
        _supported(driver, f"get_ntp_{resource}")
    elif operation in {"compare_config", "load_merge", "load_replace", "commit_config", "discard_config", "rollback"}:
        _supported(driver, "configuration")
    elif operation == "confirm_commit" and driver not in COMMIT_CONFIRM_DRIVERS:
        raise NapalmPackError(f"commit confirm is not supported by the documented {driver} driver")


def _preflight_parameters(operation: str, params: Mapping[str, Any], driver: str) -> None:
    if operation in {"compare_config", "load_merge", "load_replace", "commit_config"}:
        _config(params)
    if operation in {"compare_config", "commit_config"}:
        mode = params.get("mode", "merge")
        if mode not in {"merge", "replace"}:
            raise NapalmPackError("mode must be merge or replace")
    else:
        mode = "replace" if operation == "load_replace" else "merge"
    if operation in {"compare_config", "load_replace", "commit_config"} and mode == "replace" and params.get("confirm_replace") is not True:
        raise NapalmPackError("confirm_replace must be true for replacement operations")
    if operation in {"commit_config", "confirm_commit", "discard_config", "rollback"} and params.get("confirm") is not True:
        raise NapalmPackError("confirm must be true for this mutating operation")
    if operation == "commit_config":
        message = params.get("message", "")
        if message:
            _text(message, "message", 256)
        revert_in = params.get("revert_in")
        if revert_in is not None:
            _integer(revert_in, "revert_in", 60, 3600)
            if driver not in COMMIT_CONFIRM_DRIVERS:
                raise NapalmPackError(f"commit confirm is not supported by the documented {driver} driver")


def _execute_device(operation: str, params: Mapping[str, Any], profile: Mapping[str, Any], device: Any) -> dict[str, Any]:
    driver = profile["driver"]
    simple = {
        "get_facts": "get_facts", "get_interfaces": "get_interfaces",
        "get_interfaces_counters": "get_interfaces_counters", "get_environment": "get_environment",
        "get_bgp_neighbors": "get_bgp_neighbors", "get_optics": "get_optics",
    }
    if operation in simple:
        _supported(driver, operation)
        return {"data": getattr(device, simple[operation])()}
    if operation == "get_bgp_config":
        _supported(driver, operation)
        group = _identifier(params.get("group"), "group", optional=True)
        neighbor = params.get("neighbor") or ""
        if neighbor:
            try:
                neighbor = str(ipaddress.ip_address(neighbor))
            except ValueError as exc:
                raise NapalmPackError("neighbor must be an IP address") from exc
        return {"data": device.get_bgp_config(group=group, neighbor=neighbor)}
    if operation == "get_route_to":
        _supported(driver, operation)
        try:
            destination = str(ipaddress.ip_network(_text(params.get("destination"), "destination"), strict=False))
        except ValueError as exc:
            raise NapalmPackError("destination must be an IP prefix") from exc
        protocol = _identifier(params.get("protocol"), "protocol", optional=True)
        longer = _boolean(params.get("longer", False), "longer")
        return {"data": device.get_route_to(destination=destination, protocol=protocol, longer=longer)}
    if operation == "get_ntp":
        resource = params.get("resource", "stats")
        if resource not in {"peers", "servers", "stats"}:
            raise NapalmPackError("resource must be peers, servers, or stats")
        method = f"get_ntp_{resource}"
        _supported(driver, method)
        return {"resource": resource, "data": getattr(device, method)()}
    if operation == "get_config":
        _supported(driver, operation)
        retrieve = params.get("retrieve", "all")
        if retrieve not in {"all", "running", "candidate", "startup"}:
            raise NapalmPackError("retrieve must be all, running, candidate, or startup")
        full = _boolean(params.get("full", False), "full")
        return {"retrieve": retrieve, "sanitized": True, "data": device.get_config(retrieve=retrieve, full=full, sanitized=True, format="text")}
    if operation in {"compare_config", "load_merge", "load_replace"}:
        _supported(driver, "configuration")
        mode = params.get("mode", "merge") if operation == "compare_config" else operation.removeprefix("load_")
        if mode not in {"merge", "replace"}:
            raise NapalmPackError("mode must be merge or replace")
        if mode == "replace" and params.get("confirm_replace") is not True:
            raise NapalmPackError("confirm_replace must be true for replace previews")
        return _preview(device, mode, _config(params))
    if operation == "commit_config":
        _supported(driver, "configuration")
        if params.get("confirm") is not True:
            raise NapalmPackError("confirm must be true to commit configuration")
        mode = params.get("mode", "merge")
        if mode not in {"merge", "replace"}:
            raise NapalmPackError("mode must be merge or replace")
        if mode == "replace" and params.get("confirm_replace") is not True:
            raise NapalmPackError("confirm_replace must be true for replacement commits")
        message = params.get("message", "")
        if message:
            message = _text(message, "message", 256)
        revert_in = params.get("revert_in")
        if revert_in is not None:
            _integer(revert_in, "revert_in", 60, 3600)
            if driver not in COMMIT_CONFIRM_DRIVERS:
                raise NapalmPackError(f"commit confirm is not supported by the documented {driver} driver")
        attempted = False
        committed = False
        try:
            attempted = True
            getattr(device, f"load_{mode}_candidate")(config=_config(params))
            diff = device.compare_config()
            if not isinstance(diff, str):
                raise NapalmPackError("driver returned an invalid configuration diff")
            if not diff.strip():
                device.discard_config()
                attempted = False
                return {"changed": False, "committed": False, "mode": mode, "diff": "", "pending_commit": False}
            device.commit_config(message=message, revert_in=revert_in)
            committed = True
            pending = bool(device.has_pending_commit()) if revert_in is not None else False
            return {"changed": True, "committed": True, "mode": mode, "diff": diff, "pending_commit": pending, "revert_in": revert_in}
        finally:
            if attempted and not committed:
                device.discard_config()
    if operation == "confirm_commit":
        if driver not in COMMIT_CONFIRM_DRIVERS:
            raise NapalmPackError(f"commit confirm is not supported by the documented {driver} driver")
        if params.get("confirm") is not True:
            raise NapalmPackError("confirm must be true to confirm a pending commit")
        if not device.has_pending_commit():
            return {"changed": False, "confirmed": False, "reason": "no pending commit"}
        device.confirm_commit()
        return {"changed": True, "confirmed": True, "pending_commit": bool(device.has_pending_commit())}
    if operation == "discard_config":
        _supported(driver, "configuration")
        if params.get("confirm") is not True:
            raise NapalmPackError("confirm must be true to discard a candidate")
        device.discard_config()
        return {"changed": True, "discarded": True}
    if operation == "rollback":
        _supported(driver, "configuration")
        if params.get("confirm") is not True:
            raise NapalmPackError("confirm must be true to roll back configuration")
        device.rollback()
        return {"changed": True, "rolled_back": True}
    if operation in {"ping", "traceroute"}:
        _supported(driver, operation)
        kwargs = {
            "destination": _destination(params.get("destination")),
            "source": _destination(params["source"], "source") if params.get("source") else "",
            "ttl": _integer(params.get("ttl", 30), "ttl", 1, 64),
            "timeout": _integer(params.get("probe_timeout", 2), "probe_timeout", 1, 10),
            "vrf": _identifier(params.get("vrf"), "vrf", optional=True),
        }
        if operation == "ping":
            kwargs["size"] = _integer(params.get("size", 100), "size", 32, 9000)
            kwargs["count"] = _integer(params.get("count", 5), "count", 1, 20)
            kwargs["source_interface"] = _identifier(params.get("source_interface"), "source_interface", optional=True)
        return {"data": getattr(device, operation)(**kwargs)}
    raise NapalmPackError(f"unsupported NAPALM operation {operation!r}")


def execute_with_profile(operation: str, params: Mapping[str, Any], profile_value: Any, driver_factory: Any = None) -> dict[str, Any]:
    if operation not in _ACTION_FIELDS:
        raise NapalmPackError(f"unsupported NAPALM operation {operation!r}")
    unexpected = set(params) - _ACTION_FIELDS[operation] - {"credential_key"}
    if unexpected:
        raise NapalmPackError("action parameters contain unsupported fields")
    profile = validate_profile(profile_value)
    _preflight_support(operation, params, profile["driver"])
    _preflight_parameters(operation, params, profile["driver"])
    try:
        with DriverSession(profile, driver_factory=driver_factory) as device:
            result = _execute_device(operation, params, profile, device)
    except NapalmPackError:
        raise
    except NotImplementedError as exc:
        raise NapalmPackError(f"operation is not implemented by driver {profile['driver']}") from exc
    except Exception as exc:
        raise NapalmPackError(f"{operation} failed for driver {profile['driver']}; consult device logs") from exc
    safe = sanitize({"driver": profile["driver"], **result})
    try:
        encoded = json.dumps(safe, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NapalmPackError("driver returned invalid structured output") from exc
    if len(encoded) > profile["max_output"]:
        raise NapalmPackError("structured output exceeds the profile max_output_bytes limit")
    return safe


def execute_action(operation: str, params: Mapping[str, Any]) -> dict[str, Any]:
    profile = _fetch_key(params.get("credential_key", "napalm.credentials"))
    return execute_with_profile(operation, params, profile)
