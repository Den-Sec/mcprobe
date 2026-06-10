"""Deep get/set into nested dict/list structures addressed by a json_path string.

Path grammar: dot-separated object keys, ``[n]`` for array indices.
    "params.cmd"        -> ["params", "cmd"]
    "hosts[0]"          -> ["hosts", 0]
    "cfg.items[0].name" -> ["cfg", "items", 0, "name"]

Pure, stdlib-only. ``deep_set`` mutates and returns the passed object; callers
that must not mutate shared state (see InjectionPoint.set) deep-copy first.
"""
import re

_SEG = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def parse_path(path: str) -> list:
    segs = []
    for name, idx in _SEG.findall(path):
        segs.append(name if name else int(idx))
    return segs


def _container_for(seg) -> object:
    return [] if isinstance(seg, int) else {}


def deep_get(obj, path: str):
    cur = obj
    for seg in parse_path(path):
        cur = cur[seg]
    return cur


def deep_set(obj, path: str, value) -> object:
    segs = parse_path(path)
    cur = obj
    for i, seg in enumerate(segs[:-1]):
        nxt = segs[i + 1]
        if isinstance(seg, int):
            while len(cur) <= seg:
                cur.append(None)
            if not isinstance(cur[seg], (dict, list)):
                cur[seg] = _container_for(nxt)
            cur = cur[seg]
        else:
            if not isinstance(cur.get(seg), (dict, list)):
                cur[seg] = _container_for(nxt)
            cur = cur[seg]
    last = segs[-1]
    if isinstance(last, int):
        while len(cur) <= last:
            cur.append(None)
        cur[last] = value
    else:
        cur[last] = value
    return obj
