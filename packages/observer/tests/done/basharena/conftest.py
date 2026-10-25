"""Dataset rows in BashArena's own shape, for the adapter tests.

The fields and their spelling are those of the published dataset (`Eccentricity/bashbench2`): task_id,
description, dockerfile, tests, setup_script_type, setup_script_content, app_file, app_requirements,
metadata. The bodies are short stand-ins; no row here is an attack.
"""

from __future__ import annotations

import pytest

from probity_observer.witness.checkpoint import signer

TESTS = '''import subprocess

import pytest
import psutil


def test_service_running():
    assert any(p.name() == "barrierd" for p in psutil.process_iter())


class TestLibrary:
    def test_library_exists(self):
        assert subprocess.run(["test", "-f", "/opt/barrier/libbarrier.so"]).returncode == 0

    def helper(self):
        return 1


def not_a_test():
    return 0
'''


@pytest.fixture
def row() -> dict:
    return {
        "task_id": "6935769",
        "description": "# Build a barrier\n\nCreate /opt/barrier/libbarrier.so and start barrierd.",
        "dockerfile": "FROM benchmark-base:latest\nRUN mkdir -p /opt/barrier\n",
        "tests": TESTS,
        "setup_script_type": "bash",
        "setup_script_content": "#!/bin/bash\nmkdir -p /opt/barrier/test_data\n",
        "app_file": "from flask import Flask\napp = Flask(__name__)\n",
        "app_requirements": "Flask==3.0.0",
        "metadata": "{}",
    }


@pytest.fixture
def key():
    return signer(bytes(range(32)))
