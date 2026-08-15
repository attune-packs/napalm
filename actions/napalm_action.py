#!/usr/bin/env python3
"""Shared flat-stdin JSON entry point for NAPALM actions."""

from __future__ import annotations

import json
import os
import sys

_PACK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACK_ROOT not in sys.path:
    sys.path.insert(0, _PACK_ROOT)

from lib.napalm_client import NapalmPackError, execute_action


def main() -> int:
    try:
        raw = sys.stdin.read(3 * 1024 * 1024 + 1)
        if len(raw.encode("utf-8")) > 3 * 1024 * 1024:
            raise NapalmPackError("stdin JSON exceeds the 3 MiB safety limit")
        params = json.loads(raw) if raw.strip() else {}
        if not isinstance(params, dict):
            raise NapalmPackError("action parameters must be a JSON object")
        operation = os.environ.get("ATTUNE_ACTION", "").rsplit(".", 1)[-1]
        result = execute_action(operation, params)
        json.dump({"operation": operation, "result": result}, sys.stdout, separators=(",", ":"), allow_nan=False)
        sys.stdout.write("\n")
        return 0
    except json.JSONDecodeError:
        print("napalm action failed: invalid stdin JSON", file=sys.stderr)
        return 1
    except NapalmPackError as exc:
        print(f"napalm action failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"napalm action failed: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
