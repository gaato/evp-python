"""Run the httpwg Structured Field test suite against evp._sf."""

from __future__ import annotations

import base64
import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from evp import _sf

SUITE = Path(__file__).parent / "data" / "structured-field-tests"


def _load(directory: Path) -> list[Any]:
    return [
        pytest.param(case, id=f"{path.stem}: {case['name']}")
        for path in sorted(directory.glob("*.json"))
        for case in json.loads(path.read_text())
    ]


def _bare_to_json(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, _sf.Token):
        return {"__type": "token", "value": str(value)}
    if isinstance(value, _sf.DisplayString):
        return {"__type": "displaystring", "value": str(value)}
    if isinstance(value, _sf.Date):
        return {"__type": "date", "value": int(value)}
    if isinstance(value, bytes):
        return {"__type": "binary", "value": base64.b32encode(value).decode()}
    if isinstance(value, Decimal):
        return float(value)
    return value


def _params_to_json(params: dict[str, Any]) -> list[Any]:
    return [[k, _bare_to_json(v)] for k, v in params.items()]


def _member_to_json(member: _sf.Item | _sf.InnerList) -> list[Any]:
    if isinstance(member, _sf.InnerList):
        return [[_member_to_json(i) for i in member.items], _params_to_json(member.params)]
    return [_bare_to_json(member.value), _params_to_json(member.params)]


def _bare_from_json(value: Any) -> Any:
    if isinstance(value, dict):
        kind, raw = value["__type"], value["value"]
        return {
            "token": _sf.Token,
            "displaystring": _sf.DisplayString,
            "date": _sf.Date,
            "binary": base64.b32decode,
        }[kind](raw)
    if isinstance(value, float):
        return Decimal(repr(value))
    return value


def _params_from_json(params: list[Any]) -> dict[str, Any]:
    return {k: _bare_from_json(v) for k, v in params}


def _item_from_json(item: list[Any]) -> _sf.Item:
    value, params = item
    return _sf.Item(_bare_from_json(value), _params_from_json(params))


def _member_from_json(member: list[Any]) -> _sf.Item | _sf.InnerList:
    value, params = member
    if isinstance(value, list):
        return _sf.InnerList(tuple(_item_from_json(i) for i in value), _params_from_json(params))
    return _item_from_json(member)


def _parse(header_type: str, raw: list[str]) -> Any:
    if header_type == "item":
        return _member_to_json(_sf.parse_item(raw))
    if header_type == "list":
        return [_member_to_json(m) for m in _sf.parse_list(raw)]
    return [[k, _member_to_json(m)] for k, m in _sf.parse_dictionary(raw).items()]


def _serialize(header_type: str, expected: Any) -> str:
    if header_type == "item":
        return _sf.serialize_item(_item_from_json(expected))
    if header_type == "list":
        return _sf.serialize_list(_member_from_json(m) for m in expected)
    return _sf.serialize_dictionary({k: _member_from_json(m) for k, m in expected})


@pytest.mark.parametrize("case", _load(SUITE))
def test_parse(case: dict[str, Any]) -> None:
    kind, raw = case["header_type"], case["raw"]
    if case.get("must_fail"):
        with pytest.raises(_sf.SFError):
            _parse(kind, raw)
        return
    try:
        parsed = _parse(kind, raw)
    except _sf.SFError:
        if case.get("can_fail"):
            return
        raise
    assert parsed == case["expected"]
    canonical = case.get("canonical", raw)
    assert _serialize(kind, case["expected"]) == ",".join(canonical)


@pytest.mark.parametrize("case", _load(SUITE / "serialisation-tests"))
def test_serialize(case: dict[str, Any]) -> None:
    kind = case["header_type"]
    if case.get("must_fail"):
        with pytest.raises((_sf.SFError, ValueError)):
            _serialize(kind, case["expected"])
        return
    assert _serialize(kind, case["expected"]) == ",".join(case["canonical"])


def test_non_ascii_is_rejected() -> None:
    with pytest.raises(_sf.SFError):
        _sf.parse_item('"café"')
