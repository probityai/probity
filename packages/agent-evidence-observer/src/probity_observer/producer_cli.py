"""Small offline demonstration of broker, retry, and witnessed verification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .boundary_probe import run_boundary_probe
from .broker import Broker
from .cli import add_verify_commands, run_verify_command
from .crypto import SigningKey, canonical
from .history import Witness
from .launch.launch_agent import BACKENDS, LaunchSpec, launch
from .verify import verify_packet
from .workload_runner import run_workload


def run_demo(output: Path) -> dict[str, str]:
    """Produce a fully checkable one-write packet in an empty output directory.

    The sample uses two keys but one local operator. It demonstrates protocol
    mechanics, not an external observer or independent witness deployment.
    """
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("demo output directory must be empty")
    workspace = output / "workspace"
    workspace.mkdir()
    observer_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    witness = Witness(output / "witness-state.json", witness_key)
    history = output / "history.jsonl"
    authority = {"intervalId": "demo-interval-1", "scope": "/work", "operation": "write-file"}
    broker = Broker(workspace, history, authority, observer_key, witness)
    broker.begin()
    broker.write("request-1", "/work/result.txt", b"one durable effect\n")
    retry = broker.write("request-1", "/work/result.txt", b"one durable effect\n")
    packet = broker.seal()
    (output / "packet.json").write_bytes(canonical(packet))
    keys = {"observer": observer_key.public_hex, "witness": witness_key.public_hex}
    (output / "trusted-keys.json").write_bytes(canonical(keys))
    verified = verify_packet(packet, history, keys["observer"], keys["witness"], workspace)
    return {"status": "verified", "witnessScope": verified["witnessScope"], "noDetectedGap": str(verified["coverage"]["noDetectedGap"]).lower(), "retryReplayed": str(retry.replayed).lower()}


def _add_launch_agent(subcommands: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    agent = subcommands.add_parser(
        "launch-agent", help="run an unmodified agent in a container with three outside sensors")
    agent.add_argument("output", type=Path, help="empty directory for the run's records")
    agent.add_argument("--backend", choices=sorted(BACKENDS), required=True)
    agent.add_argument("--image", required=True, help="docker image, or apptainer .sif file")
    agent.add_argument("--workspace", type=Path, required=True)
    agent.add_argument("--claim-id", required=True)
    agent.add_argument("--invocation-id", required=True)
    agent.add_argument("--producer", default="host-observer")
    agent.add_argument("--env", action="append", default=[], metavar="KEY=VALUE")
    agent.add_argument("--network", action="store_true", help="allow network (connects are recorded)")
    agent.add_argument("--timeout", type=float, default=3600.0)
    agent.add_argument("agent_argv", nargs="+", help="the agent's command, after --")


def _launch_agent(arguments: argparse.Namespace) -> int:
    env = dict(item.split("=", 1) for item in arguments.env)
    spec = LaunchSpec(backend=arguments.backend, image=arguments.image,
                      agent_argv=tuple(arguments.agent_argv), workspace=arguments.workspace,
                      claim_id=arguments.claim_id, invocation_id=arguments.invocation_id,
                      producer=arguments.producer, env=env, network=arguments.network,
                      timeout_seconds=arguments.timeout)
    outcome = launch(spec, arguments.output)
    print(json.dumps({"agentExit": outcome.agent_exit, "coverage": outcome.coverage,
                      "launchSha256": outcome.launch_sha256,
                      "witnessScope": outcome.receipt["witnessScope"]}, sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the demonstration or verify a retained packet with pinned keys."""
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    demo = subcommands.add_parser("demo", help="write a sample packet and verify it")
    demo.add_argument("output", type=Path)
    boundary = subcommands.add_parser("boundary-probe", help="run the Linux boundary attack probe")
    boundary.add_argument("output", type=Path)
    workload = subcommands.add_parser("run-workload", help="run a Python workload behind the write broker")
    workload.add_argument("output", type=Path)
    workload.add_argument("script", type=Path)
    workload.add_argument("script_args", nargs="*")
    add_verify_commands(subcommands)
    _add_launch_agent(subcommands)
    arguments = parser.parse_args(argv)
    if arguments.command == "launch-agent":
        return _launch_agent(arguments)
    if arguments.command == "boundary-probe":
        report = run_boundary_probe(arguments.output)
        print(json.dumps(report, sort_keys=True))
        return 0 if report["status"] == "probe-passed" else 1
    if arguments.command == "run-workload":
        report = run_workload(arguments.output, arguments.script, args=arguments.script_args)
        print(json.dumps(report, sort_keys=True))
        return 0 if report["status"] == "completed" else 1
    result = run_demo(arguments.output) if arguments.command == "demo" else run_verify_command(arguments)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
