"""Inline content guard for agent tool calls: classify the exact bytes, redact or block, and leave a
signed record of every redact and block that binds the input digest.

Three properties hold by construction, each with a test:

* No secret straddles a chunk. The stream scanner keeps an overlap of ``max_match`` characters from
  the previous chunk, so a match split across two chunks is seen whole.
* A classifier that errors blocks (fail closed). The error is recorded; nothing is let through.
* A block stops the stream deterministically. The chunk that triggers a block raises, and every
  later ``feed`` raises too: no byte after the block reaches the consumer, on any run.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from probity_records import Journal, canonical

GUARD_RECORD = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/content-guard-decision"
Action = Literal["allow", "redact", "block"]


@dataclass(frozen=True)
class Finding:
    classifier: str
    start: int
    end: int

    def as_dict(self) -> dict[str, Any]:  # never the matched text: the record must not leak it
        return {"classifier": self.classifier, "end": self.end, "start": self.start}


@dataclass(frozen=True)
class Classifier:
    name: str
    pattern: re.Pattern[str]
    action: Action = "block"
    check: Callable[[str], bool] | None = None

    def find(self, text: str) -> list[Finding]:
        out = []
        for m in self.pattern.finditer(text):
            if self.check is None or self.check(m.group(0)):
                out.append(Finding(self.name, m.start(), m.end()))
        return out


def _luhn(text: str) -> bool:
    digits = [int(c) for c in text if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _entropy_ok(text: str) -> bool:
    counts = {c: text.count(c) for c in set(text)}
    entropy = -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())
    return entropy >= 3.5


def _iban(text: str) -> bool:
    s = text.replace(" ", "").upper()
    moved = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in moved)) % 97 == 1


DEFAULT_CLASSIFIERS: tuple[Classifier, ...] = (
    Classifier("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")),
    Classifier("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Classifier("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    Classifier("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,250}\b")),
    Classifier("stripe_secret", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,247}\b")),
    Classifier("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    Classifier("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,160}\.eyJ[A-Za-z0-9_-]{8,160}\.[A-Za-z0-9_-]{8,170}\b")),
    Classifier("generic_secret", re.compile(r"(?i)(?:secret|password|passwd|api[_-]?key|token)[\"'\s:=]{1,16}([A-Za-z0-9/+_\-]{20,256})"),
               check=lambda m: _entropy_ok(re.split(r"[\"'\s:=]+", m)[-1])),
    Classifier("payment_card", re.compile(r"\b\d(?:[ -]?\d){12,18}\b"), "redact", _luhn),
    Classifier("us_ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), "redact"),
    Classifier("iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b"), "redact", _iban),
    Classifier("email", re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}\b"), "redact"),
)


@dataclass(frozen=True)
class Verdict:
    action: Action
    findings: tuple[Finding, ...]
    input_sha256: str
    output: str | None = None
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"action": self.action, "findings": [f.as_dict() for f in self.findings],
                "inputSha256": self.input_sha256, "reason": self.reason}


class Blocked(Exception):  # noqa: N818 - the stream stops here
    def __init__(self, verdict: Verdict) -> None:
        super().__init__(f"content blocked: {verdict.reason or 'policy'}")
        self.verdict = verdict


@dataclass
class Guard:
    """Classify text; redact what may be masked, block what may not pass, record every non-allow."""

    classifiers: Sequence[Classifier] = DEFAULT_CLASSIFIERS
    journal: Journal | None = None
    mask: str = "[REDACTED:{name}]"
    max_match: int = 512  # the longest match any classifier needs to see whole

    def _classify(self, text: str) -> list[Finding]:
        found: list[Finding] = []
        for c in self.classifiers:
            found.extend(c.find(text))
        return sorted(found, key=lambda f: (f.start, f.end))

    def check(self, text: str, *, subject: str = "content") -> Verdict:
        digest = hashlib.sha256(text.encode()).hexdigest()
        try:
            findings = self._classify(text)
        except Exception as exc:  # noqa: BLE001 - a classifier that cannot answer blocks
            verdict = Verdict("block", (), digest, reason=f"classifier_error:{type(exc).__name__}")
            self._record(subject, verdict)
            return verdict
        actions = {c.name: c.action for c in self.classifiers}
        if any(actions[f.classifier] == "block" for f in findings):
            verdict = Verdict("block", tuple(findings), digest, reason="blocked_classifier")
        elif findings:
            verdict = Verdict("redact", tuple(findings), digest, output=self._redact(text, findings))
        else:
            return Verdict("allow", (), digest, output=text)
        self._record(subject, verdict)
        return verdict

    def _redact(self, text: str, findings: Iterable[Finding]) -> str:
        out, pos = [], 0
        for f in findings:
            if f.start < pos:
                continue  # overlapping findings: the first one already masked this span
            out.append(text[pos:f.start])
            out.append(self.mask.format(name=f.classifier))
            pos = f.end
        out.append(text[pos:])
        return "".join(out)

    def _record(self, subject: str, verdict: Verdict) -> None:
        if self.journal is not None:
            self.journal.append(GUARD_RECORD, subject, verdict.input_sha256, verdict.as_dict())

    def check_json(self, value: Any, *, subject: str = "arguments") -> Verdict:
        """Classify the canonical (JCS) text of a JSON value: what the permit path signs."""
        return self.check(canonical(value).decode(), subject=subject)

    def content_guard(self) -> Callable[[str, bytes], Mapping[str, Any]]:
        """The ``content_guard`` hook of ``probity_temporal.LocalAuthority``: blocks on block or redact,
        because arguments that a human approved cannot be rewritten on the way out."""
        def hook(tool: str, data: bytes) -> Mapping[str, Any]:
            verdict = self.check(data.decode(), subject=f"tool:{tool}")
            return {**verdict.as_dict(), "action": "allow" if verdict.action == "allow" else "block"}
        return hook

    def stream(self, *, subject: str = "stream") -> StreamGuard:
        return StreamGuard(self, subject)


@dataclass
class StreamGuard:
    """Feed chunks in order; get back the text that is safe to emit now.

    Text is held back by ``max_match`` characters so a match across a chunk boundary is classified
    whole; ``close()`` releases the tail. After a block every call raises ``Blocked``.
    """

    guard: Guard
    subject: str
    _pending: str = ""
    _blocked: Verdict | None = None
    _hasher: Any = field(default_factory=hashlib.sha256)

    def feed(self, chunk: str) -> str:
        if self._blocked is not None:
            raise Blocked(self._blocked)
        self._hasher.update(chunk.encode())
        return self._emit(self._pending + chunk, final=False)

    def _emit(self, window: str, final: bool) -> str:
        """Classify the whole window; emit only the prefix no future byte can change, held raw otherwise."""
        try:
            findings = self.guard._classify(window)  # noqa: SLF001 - same classifiers, stream-aware cut
        except Exception as exc:  # noqa: BLE001 - fail closed
            self._block(Verdict("block", (), self._hasher.hexdigest(), reason=f"classifier_error:{type(exc).__name__}"))
        actions = {c.name: c.action for c in self.guard.classifiers}
        if any(actions[f.classifier] == "block" for f in findings):
            self._block(Verdict("block", tuple(findings), self._hasher.hexdigest(), reason="blocked_classifier"))
        cut = len(window) if final else max(0, len(window) - self.guard.max_match)
        for f in findings:
            if f.start < cut < f.end:
                cut = f.start  # never emit part of a match: hold it back whole
        done = tuple(f for f in findings if f.end <= cut)
        self._pending = window[cut:]
        if done:
            out = self.guard._redact(window[:cut], done)  # noqa: SLF001
            self.guard._record(self.subject, Verdict("redact", done,  # noqa: SLF001
                                                     hashlib.sha256(window[:cut].encode()).hexdigest()))
            return out
        return window[:cut]

    def _block(self, verdict: Verdict) -> None:
        self._blocked = verdict
        self.guard._record(self.subject, verdict)  # noqa: SLF001
        raise Blocked(verdict)

    def close(self) -> str:
        if self._blocked is not None:
            raise Blocked(self._blocked)
        window, self._pending = self._pending, ""
        return self._emit(window, final=True)


def guarded_stream(guard: Guard, chunks: Iterable[str], subject: str = "stream") -> Iterator[str]:
    """Yield safe text from ``chunks``; raises ``Blocked`` at the first blocking chunk and yields nothing after."""
    sg = guard.stream(subject=subject)
    for chunk in chunks:
        out = sg.feed(chunk)
        if out:
            yield out
    tail = sg.close()
    if tail:
        yield tail


__all__ = ["DEFAULT_CLASSIFIERS", "GUARD_RECORD", "Blocked", "Classifier", "Finding", "Guard", "StreamGuard",
           "Verdict", "guarded_stream"]
