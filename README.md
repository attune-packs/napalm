# NAPALM Attune pack

Production-oriented, safety-bounded NAPALM actions for EOS, IOS, IOS-XR,
IOS-XR NETCONF, Junos, NX-OS, and NX-OS SSH. The pack uses normalized NAPALM
getters and explicit configuration transactions rather than arbitrary CLI.

## Device profile

Create one pack-owned Attune Key per device, such as `napalm.edge01`, and pass
that Key ref as `credential_key`. Password profile example:

```json
{
  "driver": "junos",
  "hostname": "edge01.example.net",
  "username": "automation",
  "password": "REDACTED",
  "known_hosts": "edge01.example.net ssh-ed25519 AAAA...",
  "timeout_seconds": 60,
  "max_output_bytes": 2097152,
  "optional_args": {
    "port": 22,
    "config_lock": true,
    "keepalive": 30
  }
}
```

SSH private keys are accepted only inside the Attune Key as
`ssh_private_key`; they are never accepted as action parameters or returned.
The worker writes key and host-key data to an execution-private temporary
directory with mode `0600`, passes only those paths to NAPALM, and removes the
directory when the connection closes. An SSH profile must provide
`known_hosts`. Agent and home-directory key discovery are disabled for
Netmiko-backed drivers. Unencrypted keys are recommended because the NAPALM
`key_file` contract has no portable passphrase argument.

EOS and NX-OS API profiles enforce HTTPS. NX-OS certificate verification is
enabled; `ca_bundle` may name an absolute worker-local CA path. EOS enables
pyeapi certificate verification. Plain HTTP, IOS telnet, disabled NX-OS TLS
verification, and arbitrary transport objects are rejected.

`optional_args` is a strict per-driver allowlist. Secret-bearing arguments,
`key_file`, SSH config paths, arbitrary backend keyword arguments, and unsafe
transport choices cannot be injected. Supported profile options are:

| Driver | Allowed `optional_args` |
|---|---|
| `eos` | `transport=https`, `port`; `lock_disable=true` is rejected |
| `ios` | `transport=ssh`, `port`, `inline_transfer`, `auto_rollback_on_error=true`, `auto_file_prompt`, `canonical_int`, `global_delay_factor` |
| `iosxr` | `port`, `config_lock`, `keepalive`, `global_delay_factor` |
| `iosxr_netconf` | `port`, `config_lock`, `config_encoding=cli|xml` |
| `junos` | `port`, `config_lock`, `keepalive`, `auto_probe`, `huge_tree` |
| `nxos` | `transport=https`, `port` |
| `nxos_ssh` | `port`, `global_delay_factor` |

Connection timeouts are limited to 5-300 seconds. Ping and traceroute have
additional probe, TTL, payload, and count bounds. Structured output defaults
to a 2 MiB limit and can be configured from 64 KiB through 10 MiB in the
profile. Candidate configuration input is limited to 2 MiB and stdin JSON to
3 MiB.

## Actions

| Action | Classification | Behavior |
|---|---|---|
| `napalm.get_facts` | read-only | Normalized inventory and uptime |
| `napalm.get_interfaces` | read-only | Interface state and attributes |
| `napalm.get_interfaces_counters` | read-only | Interface packet/error counters |
| `napalm.get_environment` | read-only | Fan, power, temperature, CPU, and memory data |
| `napalm.get_bgp_neighbors` | read-only | BGP session state across VRFs |
| `napalm.get_bgp_config` | read-only, redacted | BGP groups and neighbors; authentication keys are redacted |
| `napalm.get_route_to` | read-only | Routes for an exact or covering prefix |
| `napalm.get_optics` | read-only | OpenConfig-style transceiver data |
| `napalm.get_ntp` | read-only | One explicit `peers`, `servers`, or `stats` dataset |
| `napalm.get_config` | read-only, redacted | NAPALM-sanitized text plus additional secret-line redaction |
| `napalm.compare_config` | transient candidate mutation | Stage, compare, and always discard merge/replace text |
| `napalm.load_merge` | transient candidate mutation | Preview a merge and always discard it |
| `napalm.load_replace` | transient candidate mutation | Preview a full replacement after explicit acknowledgement, then discard |
| `napalm.commit_config` | mutating | Stage the supplied candidate and commit in one connection |
| `napalm.confirm_commit` | mutating | Confirm a pending timed commit on supported drivers |
| `napalm.discard_config` | mutating | Discard device-visible candidate state after confirmation |
| `napalm.rollback` | mutating | Invoke driver-specific rollback after confirmation |
| `napalm.ping` | read-only diagnostic | Bounded device-originated ping |
| `napalm.traceroute` | read-only diagnostic | Bounded device-originated traceroute |

Every action accepts a flat stdin JSON object and emits a stable envelope:

```json
{"operation":"get_facts","result":{"driver":"junos","data":{}}}
```

No action accepts raw usernames, passwords, private keys, enable secrets,
arbitrary optional arguments, or arbitrary CLI commands. Remote and library
exception text is suppressed because it may contain credentials or device
output. Dictionary fields matching password, secret, token, community,
authentication-key, passphrase, or private-key names are recursively redacted.

## Configuration semantics

The following controls are specifically intended to reduce configuration-loss
and cross-session commit risks.

NAPALM candidates and locks are generally connection-bound. A candidate loaded
by one Attune action cannot safely be committed by a later action after that
connection closes. Therefore `compare_config`, `load_merge`, and `load_replace`
are previews: each loads and compares in one connection and executes
`discard_config` before closing. They do not leave a candidate for
`commit_config`.

`commit_config` requires `confirm: true`, loads the exact supplied `config`,
compares it, and commits in the same connection. Empty diffs are discarded and
reported as `changed: false`. Replace previews and commits additionally require
`confirm_replace: true`; replacement text is the complete intended device
configuration and omissions can remove configuration. If staging or compare
fails after a load, the pack attempts candidate discard before closing.

A transport or connection-cleanup failure after `commit_config` reaches the
device can produce a failed Attune execution even though the device committed.
Treat that outcome as unknown: retrieve the running configuration and audit the
device commit history before retrying. Blind retry is unsafe, especially for
non-atomic merge drivers.

`revert_in` enables commit-confirm only for EOS, IOS, and Junos, is bounded to
60-3600 seconds, and returns whether NAPALM reports a pending commit. Run
`confirm_commit` before the timer expires. Support and timer behavior depend on
device OS versions; Junos needs OS 14.1 or newer according to NAPALM docs.

Standalone `discard_config` and `rollback` are deliberately marked mutating and
require confirmation. They operate on device-wide state visible to a new
session and can interfere with another operator. Rollback depth and whether a
merge is atomic are driver-specific. Use dedicated automation accounts,
configuration locks where supported, maintenance windows, out-of-band access,
and lab validation before production changes.

Diffs may contain candidate secrets even when running configuration retrieval
is sanitized. The pack replaces lines containing common credential directives
and private-key blocks before output. This conservative filter may hide benign
lines and cannot understand every vendor extension; do not place new plaintext
secrets in candidate text.

## Driver variability

This table follows the NAPALM 5.2.0 support documentation. A check mark means
the pack permits the call; device family, release, feature configuration, and
backend parser behavior can still cause a safe failure or partial fields.

| Capability | EOS | IOS | IOS-XR | IOS-XR NETCONF | Junos | NX-OS | NX-OS SSH |
|---|---:|---:|---:|---:|---:|---:|---:|
| facts, interfaces, environment, BGP neighbors, traceroute | yes | yes | yes | yes | yes | yes | yes |
| interface counters | yes | yes | yes | yes | yes | no | yes |
| BGP config | yes | yes | yes | yes | yes | no | no |
| routes | yes | no | no | no | no | no | no |
| optics | yes | yes | no | no | yes | no | yes |
| NTP peers | no | yes | yes | yes | yes | yes | yes |
| NTP servers | yes | yes | yes | yes | yes | yes | yes |
| NTP stats | yes | yes | yes | yes | yes | yes | no |
| config retrieval | yes | yes | yes | no | yes | yes | yes |
| ping | yes | yes | no | no | yes | yes | yes |
| config compare/load/commit/discard/rollback | yes | yes | yes | yes | yes | yes | no |
| commit-confirm | yes | yes | no | no | yes | no | no |

NAPALM documents EOS rollback as emulated, IOS/NX-OS merge changes as not
atomic, and NX-OS merge comparison as simplistic. IOS-XR XML-Agent comparison
is synthesized by its API. Driver getters can return empty or incomplete data
when commands, models, privileges, transceivers, VRFs, or features are absent.
The support matrix itself is generated from driver tests and can lag platform
releases; unsupported calls are rejected before opening a device connection.

## Source and deferred automation

Upstream source:
[StackStorm-Exchange/stackstorm-napalm](https://github.com/StackStorm-Exchange/stackstorm-napalm),
version `1.1.0`, revision `8af575b481a28f3a284bbb4cf7073cf72684f1d4`,
Apache-2.0. Current API review: NAPALM `5.2.0`, revision
`deafa21d1c86158d03a8e456a5fd4c9165bfb10e`. Exact provenance is in
`SOURCE.json`.

The upstream getters, configuration load, ping, and traceroute behavior were
adapted into the curated actions above. Arbitrary CLI, HTML rendering, log
retrieval, probes, SNMP, ARP, MAC, LLDP, firewall, and broad workflow examples
remain outside this second-wave surface.

The illustrative syslog/LLDP/BGP-triggered remediation sensor, rules, and
workflows are explicitly deferred and are not shipped. They accepted weakly
matched event/device data and could initiate configuration changes without the
transaction, credential, confirmation, and concurrency controls required for
production. A future event-driven design needs authenticated event provenance,
exact inventory binding, deduplication, rate limits, approval policy, durable
state, and a tested rollback path.

## Translation matrix

| Upstream behavior | Attune action | Translation |
|---|---|---|
| `get_facts`, `get_interfaces`, environment | matching `get_*` actions | Adapted to Key profiles, structured output, and support preflight |
| BGP getters | `get_bgp_neighbors`, `get_bgp_config` | Adapted; authentication material is redacted |
| routes, optics, NTP, config getters | matching `get_*` actions | Adapted to NAPALM 5.2.0 signatures and support matrix |
| `loadconfig` merge/replace plus immediate commit | previews and `commit_config` | Split into explicit non-committing previews and confirmed one-session commit |
| ping and traceroute | `ping`, `traceroute` | Adapted with strict target syntax and bounded probes |
| configuration workflow | no workflow | Replaced by explicit action contracts; approvals remain deployment policy |
| arbitrary CLI and log retrieval | none | Deferred because normalized methods are safer |
| LLDP/syslog/BGP remediation sensor and rules | none | Deferred as unsafe illustrative automation |

## Testing

Tests use only Python's standard library and deterministic mock drivers. They
make no device, DNS, Attune API, or network calls.

```bash
python -m unittest discover -s tests -v
attune pack check /home/david/Codebase/attune-packs/napalm
attune pack test /home/david/Codebase/attune-packs/napalm --detailed
```
