import pytest
from mcpsnare.inject.jsonpath import parse_path, deep_get, deep_set


def test_parse_dotted_keys():
    assert parse_path("params.cmd") == ["params", "cmd"]


def test_parse_array_index():
    assert parse_path("hosts[0]") == ["hosts", 0]


def test_parse_mixed():
    assert parse_path("cfg.items[0].name") == ["cfg", "items", 0, "name"]


def test_deep_get_nested():
    assert deep_get({"params": {"cmd": "x"}}, "params.cmd") == "x"


def test_deep_get_array():
    assert deep_get({"hosts": ["a", "b"]}, "hosts[1]") == "b"


def test_deep_set_creates_nested_object():
    assert deep_set({}, "params.cmd", "X") == {"params": {"cmd": "X"}}


def test_deep_set_preserves_siblings():
    out = deep_set({"params": {"mode": "safe"}}, "params.cmd", "X")
    assert out == {"params": {"mode": "safe", "cmd": "X"}}


def test_deep_set_creates_array():
    assert deep_set({}, "hosts[0]", "X") == {"hosts": ["X"]}


def test_deep_set_array_index_in_existing_list():
    assert deep_set({"hosts": ["a", "b"]}, "hosts[1]", "X") == {"hosts": ["a", "X"]}


def test_deep_set_array_of_objects():
    assert deep_set({}, "a[0].b", "X") == {"a": [{"b": "X"}]}
