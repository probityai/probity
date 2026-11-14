"""Argument constraints for capability grants: a check per value, and a narrowing proof per pair.

A constraint is a JSON object ``{"type": <name>, ...}``. ``check(c, value)`` says whether one argument
value satisfies it. ``narrows(child, parent)`` says whether every value the child admits is admitted
by the parent. ``narrows`` is sound and incomplete: when it cannot prove containment it answers
False, so a delegation that might widen authority is refused rather than trusted.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import posixpath
import re
import shlex
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from . import celexpr

TYPES = ("wildcard", "exact", "one_of", "not_one_of", "range", "pattern", "regex", "cidr", "url_pattern",
         "url_safe", "subpath", "shlex", "contains", "subset", "all", "any", "not", "cel")
FINITE = ("exact", "one_of")
SHELL_META = re.compile(r"[;&|`$<>\n\r(){}\\*?!#~]")


class ConstraintError(ValueError):
    """A constraint object that is not well formed."""


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _finite_values(c: dict[str, Any]) -> list[Any]:
    return [c["value"]] if c["type"] == "exact" else list(c["values"])


def _host_ok(host: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(host, p.lower()) for p in patterns)


def _star_only(pattern: str) -> bool:
    return "[" not in pattern and "?" not in pattern


def _hosts_narrow(child: list[str], parent: list[str]) -> bool:
    """Every child host pattern is one of the parent's, or both sides use only ``*`` and the child,
    read as text, matches a parent pattern: a child ``*`` can then only be consumed by a parent
    ``*``, so every host the child admits the parent admits too. A ``?`` or ``[...]`` on either
    side admits hosts a textual match cannot bound (child ``a*`` under parent ``a?``), so it narrows
    only by equality."""
    star_parents = [p for p in parent if _star_only(p)]
    return all(h in parent or (_star_only(h) and _host_ok(h, star_parents)) for h in child)


_NUMERIC_LABEL = re.compile(r"0x[0-9a-f]*|[0-9]+")
#: Percent escapes that decode to a path separator, a dot, or another escape: a server that decodes
#: them before resolving dot segments reads a different path than the one the constraint checked.
_PATH_ESCAPE = re.compile(r"%(?:2e|2f|5c|25)", re.IGNORECASE)


def _inet_aton(host: str) -> ipaddress.IPv4Address | None:
    """The IPv4 address a C resolver reads from a numeric host (``127.1``, ``0x7f.0.0.1``,
    ``0177.0.0.1``, ``2130706433``), or None when the host is not all numeric labels."""
    labels = host.split(".")
    if not 1 <= len(labels) <= 4 or not all(_NUMERIC_LABEL.fullmatch(x) for x in labels):
        return None
    values = []
    for x in labels:
        if x.startswith("0x"):
            values.append(int(x[2:] or "0", 16))
        elif len(x) > 1 and x.startswith("0"):
            values.append(int(x, 8) if set(x) <= set("01234567") else -1)
        else:
            values.append(int(x))
    *head, last = values
    if any(not 0 <= v <= 255 for v in head) or not 0 <= last < 256 ** (5 - len(values)):
        return ipaddress.IPv4Address(0)  # unparseable by every resolver: treated as private (refused)
    number = 0
    for v in head:
        number = number * 256 + v
    return ipaddress.IPv4Address(number * 256 ** (5 - len(values)) + last)


def _private_host(host: str) -> bool:
    """True for loopback, link-local, private and reserved hosts in every notation a resolver accepts.
    A DNS name that resolves to a private address is not visible here: the egress layer re-checks
    the address it actually connects to."""
    host = host.rstrip(".")
    if host in ("localhost", "localhost.localdomain") or host.endswith(".localhost"):
        return True
    numeric = _inet_aton(host)
    if numeric is not None:
        return not numeric.is_global
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return not ip.is_global


def _check_range(c: dict[str, Any], v: Any) -> bool:
    if not _number(v):
        return False
    return ("min" not in c or v >= c["min"]) and ("max" not in c or v <= c["max"])


def _check_cidr(c: dict[str, Any], v: Any) -> bool:
    try:
        return isinstance(v, str) and ipaddress.ip_address(v) in ipaddress.ip_network(c["network"])
    except ValueError:
        return False


def _url_parts(v: Any) -> tuple[str, str, str] | None:
    if not isinstance(v, str) or any(ch in v for ch in "\x00\r\n\t "):
        return None
    try:
        parts = urlsplit(v)
    except ValueError:
        return None
    if parts.username is not None or parts.password is not None or not parts.hostname:
        return None
    if "\\" in parts.path or _PATH_ESCAPE.search(parts.path):
        return None  # an encoded separator, dot or escape: the path the server resolves is not this one
    return parts.scheme.lower(), parts.hostname.lower(), parts.path or "/"


def _check_url_pattern(c: dict[str, Any], v: Any) -> bool:
    parts = _url_parts(v)
    if parts is None:
        return False
    scheme, host, path = parts
    norm = posixpath.normpath(path) if path != "/" else "/"
    prefix = c.get("pathPrefix", "/").rstrip("/")
    return (scheme in c["schemes"] and _host_ok(host, c["hosts"])
            and (not prefix or norm == prefix or norm.startswith(prefix + "/")))


def _check_url_safe(c: dict[str, Any], v: Any) -> bool:
    parts = _url_parts(v)
    if parts is None:
        return False
    scheme, host, _ = parts
    if scheme not in c.get("schemes", ["https"]):
        return False
    if c.get("denyPrivate", True) and _private_host(host):
        return False
    return "hosts" not in c or _host_ok(host, c["hosts"])


def _check_subpath(c: dict[str, Any], v: Any) -> bool:
    if not isinstance(v, str) or "\x00" in v or not v.startswith("/"):
        return False
    root = c["root"].rstrip("/") or "/"
    norm = posixpath.normpath(v)
    return norm == root or norm.startswith(root if root == "/" else root + "/")


def _check_shlex(c: dict[str, Any], v: Any) -> bool:
    if not isinstance(v, str) or SHELL_META.search(v):
        return False
    try:
        argv = shlex.split(v)
    except ValueError:
        return False
    return bool(argv) and argv[0] in c["allow"]


def _check_list(c: dict[str, Any], v: Any) -> bool:
    if not isinstance(v, list):
        return False
    if c["type"] == "contains":
        return all(item in v for item in c["values"])
    return all(item in c["values"] for item in v)


_CHECKS: dict[str, Callable[[dict[str, Any], Any], bool]] = {
    "wildcard": lambda c, v: True,
    "exact": lambda c, v: v == c["value"] and type(v) is type(c["value"]),
    "one_of": lambda c, v: any(v == x and type(v) is type(x) for x in c["values"]),
    "not_one_of": lambda c, v: v not in c["values"],
    "range": _check_range,
    "pattern": lambda c, v: isinstance(v, str) and fnmatch.fnmatchcase(v, c["pattern"]),
    "regex": lambda c, v: isinstance(v, str) and re.fullmatch(c["regex"], v) is not None,
    "cidr": _check_cidr,
    "url_pattern": _check_url_pattern,
    "url_safe": _check_url_safe,
    "subpath": _check_subpath,
    "shlex": _check_shlex,
    "contains": _check_list,
    "subset": _check_list,
    "all": lambda c, v: all(check(x, v) for x in c["of"]),
    "any": lambda c, v: any(check(x, v) for x in c["of"]),
    "not": lambda c, v: not check(c["of"], v),
    "cel": lambda c, v: celexpr.holds(c["expr"], {"value": v}),
}

_REQUIRED = {"exact": ("value",), "one_of": ("values",), "not_one_of": ("values",), "pattern": ("pattern",),
             "regex": ("regex",), "cidr": ("network",), "url_pattern": ("schemes", "hosts"), "subpath": ("root",),
             "shlex": ("allow",), "contains": ("values",), "subset": ("values",), "all": ("of",), "any": ("of",),
             "not": ("of",), "cel": ("expr",)}


def validate(c: Any) -> dict[str, Any]:
    """The constraint, when well formed; ConstraintError otherwise (an unknown type is refused)."""
    if not isinstance(c, dict) or c.get("type") not in TYPES:
        raise ConstraintError(f"unknown constraint: {c!r}")
    missing = [k for k in _REQUIRED.get(c["type"], ()) if k not in c]
    if missing:
        raise ConstraintError(f"{c['type']} needs {missing}")
    if c["type"] == "range" and not ({"min", "max"} & c.keys()):
        raise ConstraintError("range needs min or max")
    if c["type"] in ("all", "any"):
        if not isinstance(c["of"], list) or not c["of"]:
            raise ConstraintError(f"{c['type']} needs a non-empty list")
        for x in c["of"]:
            validate(x)
    if c["type"] == "not":
        validate(c["of"])
    if c["type"] == "regex":
        re.compile(c["regex"])
    if c["type"] == "cidr":
        ipaddress.ip_network(c["network"])
    if c["type"] == "cel":
        try:
            celexpr.compile_expr(c["expr"])
        except ValueError as exc:
            raise ConstraintError(str(exc)) from exc
    return c


def check(c: dict[str, Any], value: Any) -> bool:
    """Whether ``value`` satisfies constraint ``c``."""
    validate(c)
    return _CHECKS[c["type"]](c, value)


def _same_type_narrows(child: dict[str, Any], parent: dict[str, Any]) -> bool:  # noqa: PLR0911 - type dispatch
    kind = parent["type"]
    if kind == "range":
        lo_ok = "min" not in parent or ("min" in child and child["min"] >= parent["min"])
        hi_ok = "max" not in parent or ("max" in child and child["max"] <= parent["max"])
        return lo_ok and hi_ok
    if kind == "pattern":
        p = parent["pattern"]
        return child["pattern"] == p or (p.endswith("*") and "[" not in p and "?" not in p[:-1]
                                         and "*" not in p[:-1] and child["pattern"].startswith(p[:-1]))
    if kind == "cidr":
        c_net, p_net = ipaddress.ip_network(child["network"]), ipaddress.ip_network(parent["network"])
        return c_net.version == p_net.version and c_net.subnet_of(p_net)  # type: ignore[arg-type]
    if kind == "subpath":
        return _check_subpath(parent, child["root"])
    if kind == "url_pattern":
        cp, pp = child.get("pathPrefix", "/").rstrip("/"), parent.get("pathPrefix", "/").rstrip("/")
        prefix_ok = not pp or cp == pp or cp.startswith(pp + "/")
        return (set(child["schemes"]) <= set(parent["schemes"]) and prefix_ok
                and _hosts_narrow(child["hosts"], parent["hosts"]))
    if kind == "url_safe":
        hosts_ok = "hosts" not in parent or ("hosts" in child and _hosts_narrow(child["hosts"], parent["hosts"]))
        return (set(child.get("schemes", ["https"])) <= set(parent.get("schemes", ["https"])) and hosts_ok
                and (child.get("denyPrivate", True) or not parent.get("denyPrivate", True)))
    if kind in ("shlex", "subset"):
        return set(map(repr, child["allow" if kind == "shlex" else "values"])) <= set(
            map(repr, parent["allow" if kind == "shlex" else "values"]))
    if kind in ("contains", "not_one_of"):
        return set(map(repr, parent["values"])) <= set(map(repr, child["values"]))
    return child == parent  # regex, not, cel: only an identical constraint is provably no wider


def narrows(child: dict[str, Any], parent: dict[str, Any]) -> bool:
    """True only when every value ``child`` admits is provably admitted by ``parent``."""
    validate(child)
    validate(parent)
    if parent["type"] == "wildcard" or child == parent:
        return True
    if child["type"] in FINITE:
        return all(check(parent, v) for v in _finite_values(child))
    if child["type"] == "any":
        return all(narrows(x, parent) for x in child["of"])
    if parent["type"] == "all":
        return all(narrows(child, x) for x in parent["of"])
    if child["type"] == "all":
        return any(narrows(x, parent) for x in child["of"])
    if parent["type"] == "any":
        return any(narrows(child, x) for x in parent["of"])
    if child["type"] != parent["type"]:
        return False
    return _same_type_narrows(child, parent)
