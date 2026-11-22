"""Rebuild data/agent_card_schema.json from the installed a2a-sdk, and refresh data/MANIFEST.json.

    python scripts/agent_card_schema.py          # rewrite the table and the digests
    python scripts/agent_card_schema.py --check  # exit 1 when the shipped table differs

The table lists every message the Agent Card reaches, with each field's JSON name, whether it has
presence and whether the proto marks it REQUIRED. The verifier reads it to decide which members a
signed card must keep. It needs a2a-sdk, which brings the protobuf descriptors.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

DATA = Path(__file__).resolve().parent.parent / "src" / "agent_evidence_a2a" / "data"
SCHEMA = DATA / "agent_card_schema.json"


def schema() -> dict[str, Any]:
    """Walk the AgentCard descriptor and return the field table the package ships."""
    from a2a.types import AgentCard
    from google.api import field_behavior_pb2

    opaque = {"google.protobuf.Struct", "google.protobuf.Value", "google.protobuf.ListValue"}
    out: dict[str, Any] = {}

    def walk(desc: Any) -> None:
        if desc.full_name in out:
            return
        fields = []
        out[desc.full_name] = fields
        for f in desc.fields:
            mt = f.message_type
            required = field_behavior_pb2.REQUIRED in f.GetOptions().Extensions[field_behavior_pb2.field_behavior]
            free_form = mt is not None and (mt.full_name in opaque or mt.GetOptions().map_entry)
            fields.append(
                {
                    "name": f.name,
                    "json_name": f.json_name,
                    "presence": bool(f.has_presence),
                    "required": required,
                    "message": mt.full_name if mt is not None and not free_form else None,
                }
            )
            if mt is not None and not free_form:
                walk(mt)

    walk(AgentCard.DESCRIPTOR)
    return {"root": AgentCard.DESCRIPTOR.full_name, "messages": out}


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    fresh = json.loads(json.dumps(schema()))
    if argv == ["--check"]:
        same = json.loads(SCHEMA.read_text(encoding="utf-8")) == fresh
        print("agent_card_schema.json matches the installed a2a-sdk" if same else "agent_card_schema.json is stale")
        return 0 if same else 1
    _write_json(SCHEMA, fresh)
    manifest = {
        p.relative_to(DATA).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(DATA.rglob("*"))
        if p.is_file() and p.name != "MANIFEST.json"
    }
    _write_json(DATA / "MANIFEST.json", manifest)
    print(f"wrote the schema table and {len(manifest)} digests")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
