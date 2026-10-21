# Sealed pytest ids counted by the verifier

The `probity done` grader decides an SWE-shaped task from sealed pytest ids. Until this
change, every count it read came from inside the process that imports the agent's code. This
page describes the replay route that now runs those ids in the verifier's own process, the
threat it closes, the rule that decides which ids the verifier counts, and what it does not
cover.

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
cannot reach the counts) left this path open.

Counting in a process the agent's code never runs in is necessary but not sufficient. The
candidate's answers still reach that count, so a test the candidate can make pass without
being right is still a forged count, made by the verifier. The parent therefore counts an id
only when every decision in the test is a comparison it makes itself against a value the
candidate never chose (see [The counted shape](#the-counted-shape)).

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
it. An id is replayed only when its test, read from that root (for the held-out command, from
the held-out tree laid over it), has the counted shape below. An unprotected test file is the
agent's code, so it is never in the root and never runs in the verifier. `--remote` lists
every top-level module of the start and reference trees, and of their `src/` directories, that
the root does not hold, so a test that imports the candidate's package never resolves it to a
package of the verifier's own environment.

### The counted shape

`pytest_proof.py` reads the sealed source alone and proves that a test reduces to
unconditional assertions of this shape:

```python
assert <one call of a function the child serves> == <sealed literal>
```

The test passes in the verifier only if every one of those comparisons ran and held, so the
count says exactly that the candidate returned the sealed value on each sealed input. The
conditions are these, and every one is needed:

- **The test is a module-level `def`, bound once,** with no decorator but
  `pytest.mark.parametrize` over literal tables, and no parameter but the table's names. A
  fixture could hand the test a candidate object; a class or another decorator could change
  what runs.
- **The body holds only these assertions** (after an optional docstring and `pass`). No `for`,
  `while`, `if`, `try`, `with`, `return`, assignment or bare call can stand between the body
  and an assertion, so an assertion cannot be skipped on what the candidate returned.
- **The called name is bound once in the module, by an import from a module the child
  serves** (`from pkg.shapes import area`, `import pkg.shapes`, `import pkg.shapes as
  shapes`). A helper of the sealed test file, or of the verifier's environment, is not a
  candidate call.
- **Its arguments are literals or table names.** No call is nested in another, nothing the
  candidate returned is called, and nothing is unpacked.
- **The expected side is a literal, or a table name that no call in the test receives,** so
  the child never sees an expected value. It is not `None`, it can cross as plain data, and a
  boolean expectation counts only where the same function is asserted both `True` and
  `False` among the counted ids: a function that always returns one boolean, or `None`,
  satisfies a lone expectation of it.

Every other shape is not proven: a bare helper of the candidate's package
(`assert_allclose(area(2, 3), 6)`), a comparator or metric (`err(f(x), y) < tol`), a transform
of either side (`norm(f(x)) == norm(y)`), an assertion inside a loop over the candidate's
answer (`for item in solve(x): assert item == (1, 2, 3)`) or behind a branch, `pytest.raises`,
an attribute read, a fixture, a class method, a returned function (`make(2)(3) == 6`). The
compiler leaves such an id out of every replay, and only the worker counts it. The check is
fail-closed: a shape it does not recognise only withholds the verifier's count.

### The run

The runner (`runner.run_replay`) builds two directories:

- the parent's test root, which holds sealed bytes only (`pytest-root`, with the held-out
  tree laid over it when the command is held out);
- a read-only copy of the agent's whole tree, which becomes the child's `/workspace`.

The parent is the verifier's own interpreter (`python -I -m probity_observer.done.replay`).
It imports pytest first, then checks the remote names, then runs pytest in process, with
plugin autoloading off and the sealed `-c` configuration, on the sealed ids. A meta-path
finder placed ahead of the path finder serves every module under a remote name, to sealed
code only: an import must come from a file under the sealed test root, or follow a module the
candidate named. An import the verifier's own code makes is left to the path finder.
Importing a served module, reading an attribute of it and calling a function of it all cross
to the child as one request line, with a fresh nonce the reply must carry back. One reply line
comes back. Only plain data crosses, plus two handle kinds: a module, which must be a dotted
name under a remote name, and a callable, which becomes a `RemoteFunction`. A call answers
with plain data only; a function or module it returns is a failure. A builtin `Exception` the
candidate raised is raised again from its plain arguments. Anything else the candidate raised,
and every protocol failure, is `CandidateFailed`. That is a `BaseException`, so no `except
Exception` and no `pytest.raises(Exception)` in a test can turn a failure to answer into a
pass. Setting an attribute on a remote module raises `Unsupported`.

**The parent checks the proof again and makes each comparison itself.** Before running a test,
the parent proves it again from the sealed file pytest imported; a test that is not proven
fails, with its reason in the result's `unproven`. A proven test runs from an instrumented
copy of its sealed source, in which each assertion becomes a call of the parent's comparison:
the call is made there, it must make exactly one call to the child, and its value must equal
the sealed value with the same builtin type at every level (`replay.strict_eq`, so `6.0`,
`True` and `6` are three values). The test counts as passed on a run only when that copy ran
to its end with every comparison made; a passed report without it (a hook that ran something
else, or rewrote the report) counts as failed. A boolean comparison made only one way on its
function in the run withdraws the passes that rest on it (`degenerate`).

**Nothing the candidate chooses reaches the sealed code.** Outside a comparison, a reply may
carry only a handle: an import that succeeded, or an attribute that is a function or a module.
Any other reply (a plain value at import, a call from a fixture or hook, a raise) is recorded
in `outside`, fails the replay, and reaches the sealed code as `CandidateFailed` instead of
its value. Inside a comparison, the value goes to the comparison only. So no value of the
candidate's can steer sealed code into a path it opens or a file it deletes on the verifier's
host.

**The count.** A plugin object (`Count`) in the parent runs each test `repeats` times and
counts its outcomes. When pytest finishes, every request must have had one answer each time
it was asked. Each distinct request is then asked again of a fresh child, in an order seeded
from the grader key and recorded (`fresh_order`). A replay in which no call or attribute read
reached the candidate fails: it would pass on every tree (a run whose every test skipped is
one), so the compiler drops it instead of sealing a vacuous count. A replay in which any sealed
id did not pass fails. The parent writes the result file. The grade's `collected` and `passed`
for a replay command come from that file (`verify_run.grade`), never from a worker report.

**The decision.** probity-verify needs no change. `acceptance_observed/v1` already requires
every behavioural command to exit 0, and it requires `collected` and `passed` to equal the
sealed ids for every command that carries `ids`. A forged worker pass therefore cannot
outvote a replay that failed. A worker command whose ids a replay of the same kind (visible
or held-out) runs in full can only add a failure. `_isolation` now treats such a command the
way it already treats the agent's own run (`exe`). When nothing else is left that only the
worker counts, the isolation block reports `assertions_in_parent: true` and
`exit_status_alone_accepted: false`. Any command left with worker-only counts, including
every command with an id that is not proven, is listed in the staging report as
`worker_counted`, and the isolation block keeps `exit_status_alone_accepted: true`, which the
admission rule set refuses.

**Results on the fixtures** (`tests/done/test_grade_pipeline.py`, `test_pytest_replay.py`,
`test_pytest_proof.py`):

| Fixture | Before | After |
| --- | --- | --- |
| Honest fix | `supported` | `supported`, every sealed id counted by the verifier |
| Wrong answer with the recorded adversary conftest | `contradicted` | `contradicted` |
| The held-out skip special case (module patches `Function.runtest` to skip) | `not_established / sealed_tests_not_passed` | `contradicted / heldout_failed`: the held-out replay asks the held-out input, and the patch never reaches the verifier's pytest |
| Every worker result rewritten to passed, the grade signed again | (not measured) | `contradicted / acceptance_failed_in_verifier` |
| Honest fix, the sealed fail-to-pass test asserts inside a loop over the answer | replayed and counted by the verifier: `worker_counted` empty, `assertions_in_parent: true`, `exit_status_alone_accepted: false`, `supported` (measured on the first version of this change, `5b7588c`) | not replayed: `worker_counted` lists `fail-to-pass` and `heldout-fail-to-pass`, `assertions_in_parent: false`, `exit_status_alone_accepted: true` |

## What this does not cover

1. **Ids the replay does not count stay worker-counted.** Every shape the proof does not
   reach is left to the worker: helpers and comparators of the candidate's package, loops,
   branches, `pytest.raises`, attribute reads, fixtures, classes and methods, decorators
   other than literal parametrize tables, returned functions, `None` and one-way boolean
   expectations. A replay also cannot serve an instance of the candidate's class, an
   exception class the candidate defines, a package the test reaches only through a path its
   own conftest adds, or a third-party package that the verifier's interpreter lacks; such a
   test fails the replay on the reference, and stabilization drops it, either per id or as a
   whole command. Guard ids from the repository's own suite (`guard-repo`), synthesized
   tests and zero-shot `repo` commands get no replay. Many real SWE-bench tests have one of
   these shapes, so on many tasks some ids stay worker-counted, `worker_counted` names them,
   and the admission rule set refuses `supported`. This limit is on coverage, not on
   soundness: an id that was not replayed is never reported as counted by the verifier, and
   an honest refusal is the intended outcome where the verifier cannot check the test itself.
2. **A child-served helper (F1) or a gate on the candidate's answer (F2) could otherwise
   decide a test's outcome, and the replay does not count such ids.** Before the counted shape
   was required, both passed in the verifier on a wholly wrong candidate: a constant
   `assert_close` that returns `None` passes `assert_close(area(2, 3), 6)` on visible and
   held-out inputs alike, with the expected value sent to the child as an argument, and a
   candidate that returns `[]` passes `for item in solve(x): assert item == (1, 2, 3)`
   because the assertion never runs. Both shapes are now refused by the proof
   (`test_pytest_proof.py` holds each). The false pass itself is not reproduced here: no
   forging candidate was written for this change. To reproduce each end to end, an outside
   harness must supply one agent tree:
   - F1: a task whose sealed fail-to-pass test is `assert_close(area(2, 3), 6)`, with
     `assert_close` imported from the task's own package (`pkg/testing.py`), and an agent
     tree whose `pkg/testing.py` defines `assert_close` as a function that returns `None` and
     whose `area` is wrong;
   - F2: a task whose sealed fail-to-pass test is `for item in pkg.solve(1): assert item ==
     (1, 2, 3)`, and an agent tree whose `solve` returns `[]`.
   The expected grade for each is that the id is in no replay command, `worker_counted` lists
   its worker commands, and the isolation block reports `exit_status_alone_accepted: true`.
3. **A function a call returns is not called (F4).** A returned callable would come back as a
   handle named after the function that made it, so calling it would call the factory again.
   A call's reply must be plain data, or the call fails; the proof refuses a call of a call's
   result. Curried and higher-order tests are therefore not counted.
4. **The sealed test code runs in the verifier's process, on the verifier host, without a
   container.** That code is the task's own test files and conftests, sealed before the
   agent's first turn. What the candidate can do to that process is closed: no value it
   chooses reaches the sealed code except the left side of a sealed comparison, so it cannot
   steer an honest test into opening, reading or deleting a host path. What is not closed is
   a hostile task author: the sealed code runs with the verifier's user, so it can read the
   host filesystem (the grader key file, the held-out tree), reach a container runtime socket
   the verifier's user can reach, and write its own result. The trust assumption is that the
   task author's test code is not hostile to the verifier. Before this change, that code only
   ran in containers. Running the parent in a sibling container (`--network none --cap-drop
   ALL --read-only`, holding only the sealed test root, no host filesystem, no key and no
   runtime socket, with the host starting each child container beside it over stdio) would
   remove this assumption. It is not built in this change, because it is not a container
   flag: the parent needs an image that carries the verifier's own code and pytest (not the
   task image's, whose pytest the task author controls), the host must broker every child
   the parent asks for (one per distinct request for the fresh-child pass) over the parent's
   stdio, and seal-time stabilization must run the same parent as grading so that a test the
   reference passes at seal time also runs at grade time. The pytest that runs the sealed code
   is the verifier's, not the task image's, so a version difference can drop ids (point 1). It
   cannot make a wrong answer pass.
5. **A guessable expected value is only as strong as the guess is hard.** A candidate that
   returns a common value (`0`, `""`, `[]`, one constant) passes every sealed comparison whose
   value it is, held out or not. Held-out inputs catch special-casing only where the expected
   value cannot be guessed; the boolean rule covers only the two-valued case. A literal
   argument that happens to equal the expected value (`assert area(0, 5) == 0`) is the input,
   which the child sees anyway, not an oracle.
6. **A replay checks plain-data answers, not the code.** A lookup table that answers every
   sealed input correctly passes, as it would pass any test. Held-out inputs that differ from
   the visible ones are what catches special-casing. The repeats and the fresh-child pass
   catch state kept between calls.
7. **The child sees the arguments of held-out calls**, but never the expected values or the
   test source: an expected value bound by a parametrize table that a call receives makes the
   test unproven. The LiveCodeBench replay has the same property.
8. **The nonce keeps the reply stream in step, it does not authenticate the serve loop (F6).**
   The protocol stream is a duplicate of the child's original standard output, and candidate
   code in the child can read each request, write that stream and so answer with the
   request's nonce. A reply line written out of turn (at import, or twice for one request)
   fails. The purity and fresh-child checks measure the child's own answers, so a candidate
   that takes over its serve loop can keep them consistent; what it answers is still plain
   data that reaches only a sealed comparison.
9. **The finder serves sealed code only from the first import on (F5).** Once a sealed module
   has imported a remote name, `sys.modules` holds the served module, and verifier code that
   imports the same name later receives it. Every value such code asked of it outside a
   comparison would be refused by the rule above, and would fail the replay.
10. **Cost.** Each distinct request is asked again in a fresh child, which is a fresh
    container under the docker runner. A test with many distinct calls is slow, and the
    command's time limit bounds it.
11. **The in-process forgery itself is not reproduced here.** No program that forges the
    worker's counts from inside the pytest process was written for this change. The record
    test rewrites the grade to the most any such forgery could achieve, and it shows that the
    replays still decide. To reproduce the attack end to end, an outside harness must supply
    one fixture: an agent tree for the `demo__shapes-1` task with the wrong answer
    (`return w + h`), whose `pkg/shapes.py` rewrites `probity_repeat.OUTCOMES` (or registers
    a reporting hook) at import, so that every worker command exits 0 with `passed` equal to
    its sealed ids. The expected grade is that every replay command exits 1, and the verdict
    is `contradicted / acceptance_failed_in_verifier`.
12. **probity-verify does not yet refuse worker-only counts by itself.** Today a consumer gets
    that refusal from the admission rule set reading `exit_status_alone_accepted`. A consumer
    pin on `acceptance_observed/v1`, refusing a sealed id that no replay counted, is a separate
    change.
