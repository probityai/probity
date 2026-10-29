"""Acceptance commands for a real-repository task, from one zero-shot model call.

A task with no dataset acceptance (no FAIL_TO_PASS, no test field) gets its acceptance
commands and protected paths from one model call with the shipped template
``prompts/contract_v1.txt``. The answer is only a proposal: every path is checked against the
repository, every command then goes through the same three-run stability step and the mutant
adequacy measurement as a dataset task, and the compile record names the model, the template
digest and the response digest. The model is any OpenAI-compatible chat endpoint (for
example a vLLM server); the verdict itself never calls a model.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Mapping, Protocol

from .contract import DEFAULT_TEST_CMD, Task, is_test_path
from .formats import DoneError, sha256
from .repo_task import repo_files, task_from_proposal
from .runner import Runner
from .strengthen import ModelStrengthener

LISTING_LIMIT = 400
TEST_HEAD_LINES = 12
TEST_FILE_LIMIT = 20


TEMPLATES = ("contract_v1.txt", "contract_v2.txt")
DEFAULT_TEMPLATE = "contract_v2.txt"
NODE_LIMIT = 400


def template(name: str = DEFAULT_TEMPLATE) -> str:
    """A shipped template. ``contract_v2.txt`` is the default; ``contract_v1.txt`` stays so a
    recorded v1 proposal can be replayed against the prompt it was recorded with."""
    if name not in TEMPLATES:
        raise DoneError(f"unknown template {name!r}")
    return resources.files(__package__).joinpath(f"prompts/{name}").read_text("utf-8")


class Model(Protocol):
    name: str

    def complete(self, prompt: str) -> str: ...


@dataclass
class ChatModel:
    """One request to an OpenAI-compatible ``/v1/chat/completions`` endpoint.

    A reasoning model that spends ``max_tokens`` before it answers returns ``content: null``
    (``finish_reason: length``); that is a refused proposal, never a crash. The default
    budget leaves room for the reasoning (measured on gpt-oss-120b: 2 of 2 compiles at 2000
    had no content, every call at 8192 had it). ``tag`` is sent as ``X-Probity-Tag`` so a
    metering proxy books the call to its purpose.
    """

    url: str
    name: str
    max_tokens: int = 8192
    timeout: float = 300.0
    tag: str | None = None
    finish_reason: str | None = field(default=None, init=False)

    def complete(self, prompt: str) -> str:
        body = json.dumps({"model": self.name, "max_tokens": self.max_tokens, "temperature": 0,
                           "messages": [{"role": "user", "content": prompt}]}).encode()
        headers = {"Content-Type": "application/json"}
        if self.tag:
            headers["X-Probity-Tag"] = self.tag
        request = urllib.request.Request(self.url.rstrip("/") + "/v1/chat/completions", data=body,
                                         headers=headers)
        with urllib.request.urlopen(request, timeout=self.timeout) as reply:
            answer = json.loads(reply.read())
        try:
            choice = answer["choices"][0]
            content = choice["message"].get("content")
        except (KeyError, IndexError, TypeError, AttributeError) as error:
            raise DoneError("model reply has no choices[0].message") from error
        self.finish_reason = choice.get("finish_reason")
        if not isinstance(content, str) or not content.strip():
            raise DoneError(f"model answer has no content (finish_reason {self.finish_reason})")
        return content


@dataclass
class RecordedModel:
    """A recorded answer replayed byte for byte, so a contract is re-measured without a call.

    ``path`` is either a recorded call (JSON with the ``request`` and ``response`` bodies, as
    the recording relays keep them) or the bare answer text. A recorded call replays only for
    the prompt it was recorded with; a bare answer is replayed with ``prompt_matched: False``.
    """

    path: Path
    name: str = "recorded"

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        data = self.path.read_bytes()
        self.from_sha256 = sha256(data)
        self.prompt: str | None = None
        try:
            call = json.loads(data)
        except ValueError:
            call = None
        if isinstance(call, dict) and "response" in call:
            response = call["response"]
            response = json.loads(response) if isinstance(response, str) else response
            content = response["choices"][0]["message"].get("content")
            if not isinstance(content, str):
                raise DoneError("recorded answer has no content")
            self.answer = content
            request = call.get("request")
            request = json.loads(request) if isinstance(request, str) else request
            if isinstance(request, dict):
                self.prompt = request["messages"][-1]["content"]
                self.name = request.get("model", self.name)
        else:
            self.answer = data.decode("utf-8")
        self.prompt_matched = False

    def complete(self, prompt: str) -> str:
        if self.prompt is not None:
            if prompt != self.prompt:
                raise DoneError("the answer was recorded for a different prompt")
            self.prompt_matched = True
        return self.answer


def collected_nodes(repo: Path, runner: Runner, timeout: float = 300.0) -> list[str]:
    """The pytest node ids the start tree collects with its own configuration."""
    printed: list[str] = []
    runner.run(repo, DEFAULT_TEST_CMD + ("--collect-only", "--verbosity=-1"), None, timeout,
               output=printed)
    return sorted({line.strip() for text in printed for line in text.splitlines()
                   if "::" in line and not line.startswith((" ", "="))})


def render(repo: Path, task: str, name: str = DEFAULT_TEMPLATE,
           nodes: list[str] | None = None) -> str:
    """The prompt for ``task`` on ``repo``: the template filled with a listing and, for v1,
    the first lines of test files or, for v2, the collected node ids."""
    files = repo_files(repo)
    listing = "\n".join(f"{path.relative_to(repo).as_posix()} {path.stat().st_size}"
                        for path in files[:LISTING_LIMIT])
    if name == "contract_v2.txt":
        return template(name).format(task=task, listing=listing or "(empty)",
                                     listing_limit=LISTING_LIMIT, node_limit=NODE_LIMIT,
                                     nodes="\n".join((nodes or [])[:NODE_LIMIT]) or "(none)")
    heads = []
    for path in [item for item in files if is_test_path(item.relative_to(repo).as_posix())][:TEST_FILE_LIMIT]:
        lines = path.read_text("utf-8", "replace").splitlines()[:TEST_HEAD_LINES]
        heads.append(f"--- {path.relative_to(repo).as_posix()}\n" + "\n".join(lines))
    return template(name).format(task=task, listing=listing or "(empty)",
                                 listing_limit=LISTING_LIMIT, tests="\n".join(heads) or "(none found)")


@dataclass(frozen=True)
class Proposal:
    task: Task
    record: dict[str, Any]


def propose(repo: Path, task_id: str, description: str, model: Model,
            reference: Path | None = None, work: Path | None = None,
            template_name: str = DEFAULT_TEMPLATE, runner: Runner | None = None) -> Proposal:
    """One model call; the answer becomes an unsealed task with its provenance
    (:func:`.repo_task.task_from_proposal`; ``work`` is required)."""
    if work is None:
        raise DoneError("a repo task needs a work directory for its sealed configuration")
    if template_name == "contract_v2.txt" and runner is None:
        raise DoneError("the v2 template lists collected tests, so it needs a runner")
    nodes = collected_nodes(repo, runner) if template_name == "contract_v2.txt" and runner else None
    prompt = render(repo, description, template_name, nodes)
    answer = model.complete(prompt)
    task, proposed = task_from_proposal(repo, task_id, description, answer, reference, work)
    record = {"model_calls": 1, "model": model.name,
              "template": template_name,
              "template_sha256": sha256(template(template_name).encode()),
              "prompt_sha256": sha256(prompt.encode()), "response_sha256": sha256(answer.encode()),
              "finish_reason": getattr(model, "finish_reason", None), **proposed}
    if isinstance(model, RecordedModel):
        record["replay"] = {"from_sha256": model.from_sha256,
                            "prompt_matched": model.prompt_matched}
    task.notes = {"proposal": record}
    return Proposal(task, record)


def provide(repo: Path, task_id: str, description: str, *, reference: Path | None, work: Path,
            runner: Runner, options: Mapping[str, Any]
            ) -> tuple[Task, ModelStrengthener | None]:
    """The contract provider (:class:`.providers.ContractProvider`): a recorded answer
    (``model_replay``) or one call to ``model`` at ``model_url``; a live model also
    strengthens (a recorded answer cannot answer a new prompt)."""
    if options.get("model_replay"):
        model: Model = RecordedModel(Path(options["model_replay"]))
    elif options.get("model_url") and options.get("model"):
        model = ChatModel(options["model_url"], options["model"],
                          max_tokens=options.get("max_tokens") or 8192, tag=options.get("model_tag"))
    else:
        raise DoneError("a repo task needs --model-url and --model, or --model-replay")
    task = propose(repo, task_id, description, model, reference, work,
                   options.get("template") or DEFAULT_TEMPLATE, runner).task
    return task, ModelStrengthener(model) if isinstance(model, ChatModel) else None
