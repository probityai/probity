"""The producer command-line launch of an agent in docker."""

import json

from test_docker_launch import image, workspace  # noqa: F401


def test_cli_launches_and_prints_the_summary(image, workspace, tmp_path, capsys):
    from probity_observer.producer_cli import main
    code = main(["launch-agent", str(tmp_path / "cli-run"), "--backend", "docker",
                 "--image", image, "--workspace", str(workspace), "--claim-id", "cli",
                 "--invocation-id", "cli-1", "--env", "MARK=1", "--",
                 "sh", "-c", "echo $MARK > mark.txt"])
    summary = json.loads(capsys.readouterr().out)
    assert code == 0 and summary["agentExit"] == 0 and summary["coverage"] == "complete"
    assert (workspace / "mark.txt").read_text() == "1\n"
