"""The policy against an in-process owner: every branch, without a network."""

from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import urllib.error

import pytest
from probity_effects import (
    CONTRACT_ID,
    EffectGuard,
    EffectOwner,
    Journal,
    Lookup,
    NoEffect,
    Reply,
    args_digest,
    classify_failure,
    derive_key,
)

ARGS = {"quantity": 1, "sku": "A-1"}


class Owner:
    """Holds effects by key; each send behaves as the next scripted step."""

    def __init__(self, steps=(), *, answers=None, dedup=False, token=None):
        self.steps = list(steps)
        self.answers = answers  # None: answer from the ledger, finally
        self.effects: dict[str, int] = {}
        self.sends = 0
        self.lookups = 0
        self.dedup = dedup
        self.token = token

    def send(self, call):
        self.sends += 1
        step = self.steps.pop(0) if self.steps else "commit"
        if step in ("commit", "commit_lost") and not (self.dedup and call.key in self.effects):
            self.effects[call.key] = self.effects.get(call.key, 0) + 1
        if step == "commit":
            return {"order": call.key}
        if step == "refuse":
            raise NoEffect("out of stock")
        raise TimeoutError("the reply was lost")

    def lookup(self, key):
        self.lookups += 1
        if self.answers is not None:
            return self.answers.pop(0) if self.answers else None
        return Lookup(present=key in self.effects, final=True)

    def port(self, **extra):
        return EffectOwner("orders", lookup=self.lookup, deduplicates_by_key=self.dedup, lookup_interval=0,
                           lease=(lambda: self.token) if self.token is not None else None, **extra)


def test_confirmed_send_returns_the_owner_reply():
    owner = Owner(["commit"])
    outcome = EffectGuard(owner.port()).perform("create_order", ARGS, send=owner.send)
    assert (outcome.outcome, outcome.sent, outcome.value["order"]) == ("committed", 1, outcome.key)


def test_lost_reply_is_reconciled_and_never_sent_twice():
    owner = Owner(["commit_lost"])
    guard = EffectGuard(owner.port())
    results = [guard.perform("create_order", ARGS, send=owner.send) for _ in range(3)]
    assert [item.outcome for item in results] == ["committed"] * 3
    assert [item.sent for item in results] == [1, 0, 0]
    assert owner.sends == 1 and sum(owner.effects.values()) == 1


def test_lost_before_commit_is_sent_again_after_a_final_absent():
    owner = Owner(["lost", "commit"])
    outcome = EffectGuard(owner.port()).perform("create_order", ARGS, send=owner.send)
    assert (outcome.outcome, outcome.sent, owner.sends) == ("committed", 2, 2)


def test_owner_that_cannot_answer_leaves_unknown_and_blocks_a_blind_resend():
    owner = Owner(["commit_lost"], answers=[])
    guard = EffectGuard(owner.port())
    first = guard.perform("create_order", ARGS, send=owner.send)
    second = guard.perform("create_order", ARGS, send=owner.send)
    assert (first.outcome, second.outcome, second.sent, owner.sends) == ("unknown", "unknown", 0, 1)


def test_lookup_that_is_not_final_settles_nothing():
    owner = Owner(["lost"], answers=[Lookup(False, final=False)] * 5)
    outcome = EffectGuard(owner.port()).perform("create_order", ARGS, send=owner.send)
    assert (outcome.outcome, owner.sends, owner.lookups) == ("unknown", 1, 5)


def test_deduplicating_owner_gets_the_same_key_again():
    owner = Owner(["commit_lost", "commit"], dedup=True)
    outcome = EffectGuard(owner.port()).perform("create_order", ARGS, send=owner.send)
    assert (outcome.outcome, owner.sends, owner.lookups, sum(owner.effects.values())) == ("committed", 2, 0, 1)


def test_definite_no_effect_is_not_run():
    owner = Owner(["refuse"])
    outcome = EffectGuard(owner.port()).perform("create_order", ARGS, send=owner.send)
    assert (outcome.outcome, owner.sends) == ("not_run", 1) and "out of stock" in outcome.reason


def test_key_reused_with_other_arguments_is_refused_unsent():
    owner = Owner(["commit"])
    guard = EffectGuard(owner.port())
    guard.perform("create_order", ARGS, send=owner.send, key="order-1")
    outcome = guard.perform("create_order", {"quantity": 2, "sku": "A-1"}, send=owner.send, key="order-1")
    assert (outcome.outcome, owner.sends) == ("not_run", 1)


def test_lost_lease_sends_nothing():
    owner = Owner(["commit"], token=8)
    outcome = EffectGuard(owner.port()).perform("create_order", ARGS, send=owner.send, fencing_token=7)
    assert (outcome.outcome, owner.sends) == ("not_run", 0)


def test_send_limit_bounds_resends():
    owner = Owner(["lost", "lost", "lost", "commit"])
    outcome = EffectGuard(owner.port(max_sends=3)).perform("create_order", ARGS, send=owner.send)
    assert (outcome.outcome, owner.sends) == ("not_run", 3)


def test_owner_send_takes_precedence_over_the_body():
    owner = Owner(["commit"])
    outcome = EffectGuard(owner.port(send=owner.send)).perform("create_order", ARGS, send=lambda call: 1 / 0)
    assert outcome.outcome == "committed"


def test_a_stop_after_dispatch_is_reconciled_by_the_next_process(tmp_path):
    owner = Owner(["commit"])
    path = tmp_path / "journal.jsonl"

    class Stop(BaseException):
        pass

    def stopping_send(call):
        owner.send(call)
        raise Stop()

    with pytest.raises(Stop):
        EffectGuard(owner.port(), Journal.open(path)).perform("create_order", ARGS, send=stopping_send)
    outcome = EffectGuard(owner.port(), Journal.open(path)).perform("create_order", ARGS, send=owner.send)
    assert (outcome.outcome, outcome.sent, owner.sends) == ("committed", 0, 1)
    record = Journal.open(path).record(outcome.key, owner_effects=1)
    assert record["attempts"][0]["reply"] == "connection_lost"
    assert record["reconciliations"][0]["result"] == "present"


def test_torn_last_line_is_ignored_and_earlier_lines_are_kept(tmp_path):
    path = tmp_path / "journal.jsonl"
    owner = Owner(["commit"])
    EffectGuard(owner.port(), Journal.open(path)).perform("create_order", ARGS, send=owner.send)
    path.write_text(path.read_text() + '{"event": "dis', encoding="utf-8")
    assert len(Journal.open(path).keys()) == 1


def test_record_is_the_uncertain_effect_contract():
    owner = Owner(["commit_lost"])
    journal = Journal()
    outcome = EffectGuard(owner.port(), journal).perform("create_order", ARGS, send=owner.send, key="order-7f3a")
    record = journal.record(outcome.key, owner_effects=1)
    assert record["contractId"] == CONTRACT_ID
    assert record["operation"] == {"action": "create_order", "argsDigest": args_digest(ARGS), "id": "order-7f3a",
                                   "idempotencyKey": "order-7f3a"}
    assert [item["reply"] for item in record["attempts"]] == ["timeout"]
    assert record["reported"] == {"outcome": "committed"} and record["ownerEffects"] == 1
    assert "ownerEffects" not in journal.trail(outcome.key)
    with pytest.raises(ValueError):
        journal.record(outcome.key, owner_effects=-1)


def test_args_digest_is_over_rfc_8785_bytes():
    expected = "sha256:" + hashlib.sha256(b'{"a":[1,1e+30],"b":1}').hexdigest()
    assert args_digest({"b": 1, "a": [1.0, 1e30]}) == expected
    assert derive_key("create_order", ARGS, "t1") == derive_key("create_order", dict(reversed(ARGS.items())), "t1")
    assert derive_key("create_order", ARGS, "t1") != derive_key("create_order", ARGS, "t2")


@pytest.mark.parametrize(("error", "reply"), [
    (NoEffect("refused"), Reply.NO_EFFECT),
    (ConnectionRefusedError(), Reply.NO_EFFECT),
    (socket.gaierror(), Reply.NO_EFFECT),
    (TimeoutError(), Reply.TIMEOUT),
    (ConnectionResetError(), Reply.CONNECTION_LOST),
    (urllib.error.HTTPError("u", 400, "bad", None, None), Reply.NO_EFFECT),
    (urllib.error.HTTPError("u", 409, "conflict", None, None), Reply.CONNECTION_LOST),
    (urllib.error.HTTPError("u", 504, "gateway", None, None), Reply.TIMEOUT),
    (urllib.error.HTTPError("u", 500, "error", None, None), Reply.CONNECTION_LOST),
    (urllib.error.URLError(ConnectionRefusedError()), Reply.NO_EFFECT),
    (ValueError("bug after the request left"), Reply.CONNECTION_LOST),
])
def test_failures_are_read_conservatively(error, reply):
    assert classify_failure(error) is reply


def test_httpx_connect_phase_is_no_effect_and_read_timeout_is_lost():
    httpx = pytest.importorskip("httpx")
    assert classify_failure(httpx.ConnectError("refused")) is Reply.NO_EFFECT
    assert classify_failure(httpx.ReadTimeout("slow")) is Reply.TIMEOUT
    assert classify_failure(httpx.RemoteProtocolError("closed")) is Reply.CONNECTION_LOST


def test_async_perform_runs_the_same_policy():
    owner = Owner(["commit_lost"])

    async def send(call):
        return owner.send(call)

    async def lookup(key):
        return owner.lookup(key)

    port = EffectOwner("orders", lookup=lookup, lookup_interval=0)
    guard = EffectGuard(port)
    first = asyncio.run(guard.aperform("create_order", ARGS, send=send))
    second = asyncio.run(guard.aperform("create_order", ARGS, send=send))
    assert (first.outcome, second.outcome, owner.sends) == ("committed", "committed", 1)


def test_journal_lines_are_json(tmp_path):
    path = tmp_path / "journal.jsonl"
    owner = Owner(["commit"])
    EffectGuard(owner.port(), Journal.open(path)).perform("create_order", ARGS, send=owner.send)
    kinds = [json.loads(line)["event"] for line in path.read_text().splitlines()]
    assert kinds == ["operation", "dispatch", "reply", "outcome"]
