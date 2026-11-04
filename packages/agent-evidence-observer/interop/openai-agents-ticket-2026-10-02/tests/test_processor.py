"""Real SDK lifecycle, payload-default and isolated callback failure controls."""

from __future__ import annotations

from typing import Any

import pytest
from agents import agent_span, custom_span, generation_span, set_trace_processors, trace

from probity_openai.contract import encode
from probity_openai.processor import LocalTraceProcessor


@pytest.mark.parametrize("capture", [False, True])
def test_native_capture_default_and_explicit_payloads(capture: bool) -> None:
    processor = LocalTraceProcessor(capture_payloads=capture)
    set_trace_processors([processor])
    sentinel = "synthetic-sensitive-sentinel"
    with trace(sentinel, metadata={"private": sentinel}):
        with agent_span(sentinel):
            with generation_span(model=sentinel, input=[{"private": sentinel}]):
                pass
            with custom_span(sentinel, data={"private": sentinel}):
                pass
    processor.shutdown()
    processor.shutdown()
    value = processor.snapshot()
    assert value["failures"] == 0
    assert value["shutdowns"] == 1
    assert len(value["events"]) == 8
    assert (sentinel in encode(value).decode()) == capture


def test_callback_serialization_failure_has_no_payload_or_log(capsys: Any) -> None:
    class Unexportable:
        def export(self) -> None:
            raise RuntimeError("synthetic-sensitive-exception")

    processor = LocalTraceProcessor()
    processor.on_trace_start(Unexportable())
    processor.shutdown()
    value = processor.snapshot()
    assert value["failures"] == 1
    assert value["events"] == []
    assert "synthetic-sensitive" not in encode(value).decode()
    assert capsys.readouterr() == ("", "")


def test_closed_processor_counts_late_callbacks() -> None:
    processor = LocalTraceProcessor()
    processor.shutdown()
    processor.on_trace_start(None)
    assert processor.snapshot()["failures"] == 1
