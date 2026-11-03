"""The open referee factories: the referee's parts over a signed file store, and nothing else.

They run in the referee's own process (`ratchet.improve.referee.ProcessReferee`), which names them by
`module:function`; `ratchet.improve.referee.factory_name` picks this module unless the referee configuration
(`factory`) or RATCHET_REFEREE_FACTORY names another module that defines the same two functions. The
decision key comes from RATCHET_SIGNING_KEY or the keyring, and the records go to a file store signed with
it. There is no database store here, and no stored decision a policy could re-judge (`RefereeParts.decisions`
stays None, so a driver that names `db:version` is refused by the referee).

`case_suite_parts` (`ratchet evolve`, `ratchet.improve.run`) takes the agent model from the RATCHET_* model
variables:

    config = {"cases": "heldout" | [held-out case ids], "store": {"kind": "file", "dir": ...},
              "workers": 8, "repeats": 1, "suite_digest": "...", "model_config": {...}, "results_dir": ...}

`policy_parts` (`run_det`) builds the worker from an endpoint configuration the driver names by file and
digest (`ratchet.improve.endpoints`):

    config = {... as above, "endpoints": {"file": ..., "digest": ...},
              "worker": "round_robin" (seeded) | "spread" (unseeded) | "per_repetition",
              "replicas_file": ... (per_repetition only)}
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from ratchet.improve.referee import RefereeError, RefereeParts


def case_suite_parts(config: Mapping[str, Any]) -> RefereeParts:
    """The case-suite referee around the agent model the RATCHET_* model variables name."""
    from ratchet.agent.model import ModelClient

    stack = ExitStack()
    try:
        return parts(config, stack.enter_context(ModelClient.from_env()), stack)
    except BaseException:
        stack.close()
        raise


def policy_parts(config: Mapping[str, Any]) -> RefereeParts:
    """The worker from the endpoint configuration the driver passed by reference, refused when the file is
    not the one its digest names."""
    from ratchet.agent.worker import run_case
    from ratchet.improve import endpoints as ep

    stack = ExitStack()
    try:
        endpoints = ep.resolve(config["endpoints"])
        overrides: dict[str, Any] = {"model_config": endpoints.model_config()}
        if config.get("worker") == "per_repetition":
            replicas = Path(config["replicas_file"]) if config.get("replicas_file") else None
            reps = ep.PerRepetition(endpoints, replicas)
            stack.callback(reps.close)
            overrides["repetitions"] = reps
        else:
            spread = ep.RoundRobin(endpoints, run_case, seeded=config.get("worker") == "round_robin")
            stack.callback(spread.close)
            overrides |= {"run_case": spread, "workers": int(config.get("workers") or len(endpoints.urls))}
        return parts(config, None, stack, **overrides)
    except BaseException:
        stack.close()
        raise


def held_out(selection: Any) -> list[Any]:
    """The held-out cases a configuration selects from the installed case suite."""
    from ratchet_cases.cases import all_cases

    every = {c.id: c for c in all_cases()}
    if selection == "heldout":
        return [c for c in every.values() if c.split == "heldout"]
    missing = [i for i in selection if i not in every]
    if missing:
        raise RefereeError(f"unknown held-out case ids {missing}")
    return [every[i] for i in selection]


def parts(config: Mapping[str, Any], model: Any, stack: ExitStack, **overrides: Any) -> RefereeParts:
    """The referee's parts around a given agent model; `stack` (closed with the parts) owns what it opened.
    `overrides` replace parts (the worker, the guard runner, the model configuration)."""
    from ratchet_cases.cases import all_cases

    from ratchet.agent.worker import run_case
    from ratchet.improve.receipt import Signer
    from ratchet.improve.worldsim import WorldSimulator
    from ratchet.store.file_store import FileActivator, FileStore

    spec = config["store"]
    if spec.get("kind") != "file":
        raise RefereeError(f"the open referee keeps a signed file store only, not {spec.get('kind')!r}")
    signer = Signer.for_decisions()
    store = FileStore(Path(spec["dir"]), key=signer.private_key)
    fields: dict[str, Any] = dict(
        cases=held_out(config["cases"]),
        run_case=run_case,
        model=model,
        simulator=WorldSimulator(all_cases()),
        signer=signer,
        store=store,
        activator=FileActivator(store),
        model_config=dict(config.get("model_config", {})),
        suite_digest=config.get("suite_digest"),
        workers=int(config.get("workers", 8)),
        repeats=int(config.get("repeats", 1)),
        session_bundles={str(k): Path(v) for k, v in config.get("session_bundles", {}).items()},
        results_dir=Path(config["results_dir"]) if config.get("results_dir") else None,
        close=stack.close,
    )
    if "runner" not in overrides:
        fields["runner"] = _guard_runner(stack)
    return RefereeParts(**(fields | overrides))


def _guard_runner(stack: ExitStack) -> Any:
    """The sandboxed guard runner the referee replays candidate guards with."""
    from ratchet.agent.guards import GuardRuntime
    from ratchet.improve.sandbox import SandboxRunner

    return SandboxRunner(stack.enter_context(GuardRuntime()))
