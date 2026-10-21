# Sealed pytest ids counted by the verifier

The `probity done` grader decides an SWE-shaped task from sealed pytest ids. Until this
change, every count it read came from inside the process that imports the agent's code. This
page describes the replay route that now runs those ids in the verifier's own process, the
threat it closes, and what it does not cover.

## The threat

A sealed pytest command runs `python -P -c <boot> ../heldout/config/probity-plugins ... -p
probity_repeat <ids>` in a fresh, locked-down container. The `probity_repeat` plugin counts
each test's outcomes and prints one HMAC-keyed report line. The grade reads two things from
that run: the exit status, and the `collected` and `passed` counts taken from the report.

Both come from one process, and the agent's module (`pkg/shapes.py`, `func.py`) is imported
into that process. Code at module level in the agent's file runs before any test body, so it
can do any of these:

- read `sys.modules["probity_repeat"].KEY` and sign a report of its own;
- rewrite `probity_repeat.OUTCOMES` so the one real report carries forged counts;
- register a hook on the plugin manager, or patch `_pytest`, so that failing tests are
  reported as passed and pytest exits 0.

The container limits what the code can reach outside the process. It does nothing about what
the code can do inside it. A junit file written by the worker has the same weakness, because
it is also written from inside that process, and its path is visible in `sys.argv`. Earlier
fixes (#83 sealed the ids and the passed count, #86 showed that a conftest in the agent's tree
cannot reach the counts) left this path open. The only counts the agent's code cannot touch are
counts produced in a process it never runs in.

## The design

The LiveCodeBench grader already avoids this problem. It runs the sealed test in a trusted
parent process and sends each `candidate(...)` call to an isolated child as type-tagged plain
data (`replay.py`). This change takes the same route for sealed pytest ids
(`pytest_replay.py`).

**The contract.** `swe_task` seals up to three extra acceptance commands beside the worker
commands: `fail-to-pass-replay`, `pass-to-pass-replay` and `heldout-fail-to-pass-replay`.
Each one carries `ids` like any sealed pytest command. The argv is fixed in shape:

```
probity-done-replay --pytest --config ../heldout/config/pytest.ini --overlay <-|../heldout/tree>
    --remote <top-level names> --repeats 2 -- <ids...>
```

The compiler also writes `<heldout>/pytest-root`, a copy of every protected path of the start
tree: the test files, `conftest.py` files and pytest configuration. The heldout digest covers
it. An id is replayed only when its test file is in that root, or, for the held-out command,
in the held-out tree laid over it. An unprotected test file is the agent's code, so it never
runs in the verifier. `--remote` lists every top-level module of the start and reference
trees, and of their `src/` directories, that the root does not hold, so a test that imports
the candidate's package never resolves it to a package of the verifier's own environment.

**The run.** The runner (`runner.run_replay`) builds two directories:

- the parent's test root, which holds sealed bytes only (`pytest-root`, with the held-out
  tree laid over it when the command is held out);
- a read-only copy of the agent's whole tree, which becomes the child's `/workspace`.

The parent is the verifier's own interpreter (`python -I -m probity_observer.done.replay`).
It runs pytest in process, with plugin autoloading off and the sealed `-c` configuration, on
the sealed ids. A meta-path finder placed ahead of the path finder serves every module under
a remote name. Importing one, reading an attribute of it and calling a function of it all
cross to the child as one request line. One reply line comes back. Only plain data crosses,
plus two handle kinds: a module, which must lie under a remote name, and a callable, which
becomes a `RemoteFunction`. A builtin `Exception` the candidate raised is raised again from
its plain arguments, so `pytest.raises(ValueError)` works. Anything else the candidate raised,
and every protocol failure, is `CandidateFailed`. That is a `BaseException`, so no `except
Exception` and no `pytest.raises(Exception)` in a test can turn a failure to answer into a
pass. Setting an attribute on a remote module raises `Unsupported`.

**The count.** A plugin object (`Count`) in the parent runs each test `repeats` times and
counts its outcomes. When pytest finishes, every request must have had one answer each time
it was asked. Each distinct request is then asked again of a fresh child, in an order seeded
from the grader key and recorded (`fresh_order`). A replay in which no call or attribute
read reached the candidate fails: it would pass on every tree, so the compiler drops it
instead of sealing a vacuous count. The parent writes the result file. The
grade's `collected` and `passed` for a replay command come from that file
(`verify_run.grade`), never from a worker report.

**The decision.** probity-verify needs no change. `acceptance_observed/v1` already requires
every behavioural command to exit 0, and it requires `collected` and `passed` to equal the
sealed ids for every command that carries `ids`. A forged worker pass therefore cannot
outvote a replay that failed. A worker command whose ids a replay of the same kind (visible
or held-out) runs in full can only add a failure. `_isolation` now treats such a command the
way it already treats the agent's own run (`exe`). When nothing else is left that only the
worker counts, the isolation block reports `assertions_in_parent: true` and
`exit_status_alone_accepted: false`. Any command left with worker-only counts is listed in
the staging report as `worker_counted`.

**Results on the fixtures** (`tests/done/test_grade_pipeline.py`, `test_pytest_replay.py`):

| Fixture | Before | After |
| --- | --- | --- |
| Honest fix | `supported` | `supported`, every sealed id counted by the verifier |
| Wrong answer with the recorded adversary conftest | `contradicted` | `contradicted` |
| The held-out skip special case (module patches `Function.runtest` to skip) | `not_established / sealed_tests_not_passed` | `contradicted / heldout_failed`: the held-out replay asks the held-out input, and the patch never reaches the verifier's pytest |
| Every worker result rewritten to passed, the grade signed again | (not measured) | `contradicted / acceptance_failed_in_verifier` |

## What this does not cover

1. **Ids the replay cannot serve stay worker-counted.** A test needs a replay that can serve
   it. It is not replayed when it needs an instance of the candidate's class, an exception
   class the candidate defines, a fixture that yields candidate objects, a monkeypatched
   attribute, a package the test reaches only through a path its own conftest adds, or a
   third-party package that the verifier's interpreter lacks. Such a test fails the replay on the reference, and stabilization drops it, either
   per id or as a whole command. Guard ids from the repository's own suite (`guard-repo`),
   synthesized tests and zero-shot `repo` commands get no replay. For all of these, the count
   is still the worker's. `worker_counted` names them, and the isolation block keeps
   `exit_status_alone_accepted: true`, which the admission rule set refuses. This limit is
   on coverage, not on soundness: an id that was not replayed is never reported as counted
   by the verifier.
2. **The sealed test code now runs in the verifier's process, on the verifier host.** That
   code is the task's own test files and conftests, sealed before the agent's first turn,
   and they run there without a container. The trust assumption is that the task author's
   test code is not hostile to the verifier. Before this change, that code only ran in
   containers. The pytest that runs it is the verifier's, not the task image's, so a
   version difference can drop ids (point 1). It cannot make a wrong answer pass.
3. **A replay checks plain-data answers, not the code.** A lookup table that answers every
   sealed input correctly passes, as it would pass any test. Held-out inputs that differ from
   the visible ones are what catches special-casing. The repeats and the fresh-child pass
   catch state kept between calls.
4. **The child sees the arguments of held-out calls**, but never the expected values or the
   test source. The LiveCodeBench replay has the same property.
5. **Cost.** Each distinct request is asked again in a fresh child, which is a fresh
   container under the docker runner. A test with many distinct calls is slow, and the
   command's time limit bounds it.
6. **The in-process forgery itself is not reproduced here.** No program that forges the
   worker's counts from inside the pytest process was written for this change. The record
   test rewrites the grade to the most any such forgery could achieve, and it shows that the
   replays still decide. To reproduce the attack end to end, an outside harness must supply
   one fixture: an agent tree for the `demo__shapes-1` task with the wrong answer
   (`return w + h`), whose `pkg/shapes.py` rewrites `probity_repeat.OUTCOMES` (or registers
   a reporting hook) at import, so that every worker command exits 0 with `passed` equal to
   its sealed ids. The expected grade is that every replay command exits 1, and the verdict is
   `contradicted / acceptance_failed_in_verifier`.
7. **probity-verify does not yet refuse worker-only counts by itself.** Today a consumer gets
   that refusal from the admission rule set reading `exit_status_alone_accepted`. A consumer
   pin on `acceptance_observed/v1`, refusing a sealed id that no replay counted, is a separate
   change.
