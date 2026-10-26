"""Mutation check for the observer half of the out-of-tree tamper rules: every mutant must
turn the tests red.

Each mutant deletes or weakens one rule: the replay's failure kind, the child loop's private
helpers, the sealed execution surface, the in-process twin, or the trace's link following.
Each is applied to the source, the tests run, and the file is restored. Run from
``packages/observer`` in an environment with the ``test`` and ``done`` extras:

    python scripts/mutate-oot-rules.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path("src/probity_observer")
REPLAY = ROOT / "done" / "replay.py"
CONTRACT = ROOT / "done" / "contract.py"
STRACE = ROOT / "sensors" / "strace.py"
TESTS = ["tests/done/test_out_of_tree_seal.py"]
MUTANTS = [
    # The replay's failure kind.
    (REPLAY, '        return "assertion" if failure in IMPORT_FAILURES else "candidate"',
     '        return "assertion"'),
    (REPLAY, 'if failure.startswith("assertion") and not result.get("impure") and not result.get(',
     'if failure.startswith("assertion") and not result.get('),
    (REPLAY, '            "fresh_mismatch"):\n        return "assertion"',
     '            "impure"):\n        return "assertion"'),
    (REPLAY, 'EXIT_ERRORS = ("import:SystemExit", "SystemExit", "child-exited")',
     'EXIT_ERRORS = ("import:SystemExit", "SystemExit")'),
    (REPLAY, '    if result.get("mode", "assert") != "assert" or result.get("timed_out"):',
     '    if result.get("mode", "assert") != "assert":'),
    (REPLAY, '        result["failure_kind"] = kind\n', '        pass\n'),
    (REPLAY, '            and error not in ISOLATION_ERRORS and not result.get("impure")',
     '            and not result.get("impure")'),
    (REPLAY, '    if (error is not None and error.isidentifier() and error not in PROTOCOL_ERRORS',
     '    if (error is not None and error.isidentifier()'),
    (REPLAY, '        error = error[len("import:"):]', '        pass'),
    (REPLAY, '                    reply = {"error": "unplain"}', '                    reply = {"error": "TypeError"}'),
    # The child loop keeps its helpers out of __main__.
    (REPLAY, 'return (CHILD_LOOP + f"_serve(', 'return ("_proto = None\\n" + CHILD_LOOP + f"_serve('),
    # The sealed surface.
    (CONTRACT, 'SURFACE_FORBIDDEN = frozenset({"/", "/tmp", "/var/tmp", AGENT_HOME})',
     'SURFACE_FORBIDDEN = frozenset({"/", "/var/tmp"})'),
    (CONTRACT, '        return path not in SURFACE_FORBIDDEN and not _over(path, AGENT_CWD)',
     '        return path not in SURFACE_FORBIDDEN'),
    (CONTRACT, '    entries = [path for path in reals\n'
               '               if not any(other != path and _over(path, other) for other in reals)]',
     '    entries = reals'),
    (CONTRACT, '               if name != real and allowed(name) and allowed(real)',
     '               if False'),
    (CONTRACT, '        record["execution_surface"] = list(surface[0])',
     '        pass'),
    # The in-process twin.
    (CONTRACT, 'IN_PROCESS_TWINS = {"lcb": {"visible_run": "visible"}}', 'IN_PROCESS_TWINS = {}'),
    (CONTRACT, '        twin = IN_PROCESS_TWINS.get(task.source, {}).get(command.id)',
     '        twin = IN_PROCESS_TWINS["lcb"].get(command.id)'),
    # The trace's link following.
    (STRACE, '        return self.follow(posixpath.normpath(value))', '        return posixpath.normpath(value)'),
    (STRACE, '            head = posixpath.dirname(name)', '            head = name'),
    (STRACE, '                    resolve.made_link(fields["path"], string_arg(args[0]))', '                    pass'),
    (STRACE, '            self.links[name] = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))',
     '            self.links[name] = posixpath.normpath(target)'),
    (STRACE, '        raise Unresolved(name)', '        return name'),
    (STRACE, 'ESCAPE = ("io_uring_setup", "ptrace", "process_vm_writev", "open_by_handle_at")',
     'ESCAPE = ("io_uring_setup", "ptrace", "process_vm_writev")'),
]


def run() -> int:
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
                           *TESTS], capture_output=True, check=False).returncode


def main() -> int:
    if run() != 0:
        print("BASELINE RED")
        return 1
    survived = 0
    for index, (path, old, new) in enumerate(MUTANTS):
        source = path.read_text()
        if source.count(old) != 1:
            print(f"MUTANT {index} NOT APPLICABLE ({path.name})")
            survived += 1
            continue
        try:
            path.write_text(source.replace(old, new, 1))
            code = run()
        finally:
            path.write_text(source)
        print(f"MUTANT {index} {path.name} {'KILLED' if code != 0 else 'SURVIVED'}")
        survived += code == 0
    print(f"MUTANTS {len(MUTANTS)} surviving={survived}")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
