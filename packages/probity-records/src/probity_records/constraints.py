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

from . import celexpr
from .core import ascii_lower, decimal, value_key

TYPES = ("wildcard", "exact", "one_of", "not_one_of", "range", "pattern", "regex", "cidr", "url_pattern",
         "url_safe", "subpath", "shlex", "contains", "subset", "all", "any", "not", "cel")
FINITE = ("exact", "one_of")
SHELL_META = re.compile(r"[;&|`$<>\n\r(){}\\*?!#~]")


class ConstraintError(ValueError):
    """A constraint object that is not well formed."""


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def same(a: Any, b: Any) -> bool:
    """Whether two parsed JSON values are one JSON value, by ``core.value_key`` (the TypeScript twin's ``same`` reads the
    same bytes): object members in any order are one object, ``3`` and ``3.0`` are one number, and ``true`` is never
    ``1`` where Python's ``==`` calls them equal. A value jcs-admit refuses (a lone surrogate, NaN) equals nothing."""
    try:
        return value_key(a) == value_key(b)
    except ValueError:
        return False


def _member(v: Any, values: list[Any]) -> bool:
    return any(same(v, x) for x in values)


def _keys(values: list[Any]) -> set[bytes] | None:
    """The value keys of a list, or None when one of its values is one jcs-admit refuses."""
    try:
        return {value_key(x) for x in values}
    except ValueError:
        return None


def _finite_values(c: dict[str, Any]) -> list[Any]:
    return [c["value"]] if c["type"] == "exact" else list(c["values"])


def _host_ok(host: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(host, ascii_lower(p)) for p in patterns)


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


#: ``grammar/constraint-url.json``: the one reader of a URL a constraint is asked about. Each pattern is the grammar
#: file's, read with ``fullmatch`` (the twin anchors the same text), and none uses ``\d`` or a case-blind flag.
URI_TEXT = re.compile(r"(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*")
URL = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]*)([^?#]*)(?:[?#].*)?")
AUTHORITY = re.compile(r"(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.\-]+)(?::([1-9][0-9]{0,4}))?")
HOST_LABEL = re.compile(r"[A-Za-z0-9\-]{1,63}")
NUMERIC_LABEL = re.compile(r"[0-9]+|0[xX][0-9A-Fa-f]*")
IPV4 = re.compile(r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}")
PATH = re.compile(r"(?:/(?!\.\.?(?:/|$))[^/]+)*/?")
#: Percent escapes that decode to a dot, a path separator or another escape: a server that decodes them before it
#: resolves dot segments reads a different path than the one the constraint checked.
PATH_ESCAPE = re.compile(r"%(?:2[EeFf]|5[Cc]|25)")
PORT_MAX = 65535
HOST_MAX = 253


def url_parts(v: Any) -> tuple[str, str, int | None, str] | None:
    """(scheme, host, port, path) of a URL ``grammar/constraint-url.json`` accepts, else None.

    Scheme and host come back in ASCII lower case, an IPv6 literal without its brackets, an empty path as ``/``. No
    platform URL parser reads the text: ``urlsplit`` and WHATWG URL parsing each repair what the other refuses, so the
    twin ``urlParts`` and this function read the same grammar instead and refuse the same texts."""
    if not isinstance(v, str) or not URI_TEXT.fullmatch(v):
        return None
    url = URL.fullmatch(v)
    if url is None:
        return None
    authority = AUTHORITY.fullmatch(url[2])
    path = url[3] or "/"
    if authority is None or not PATH.fullmatch(path) or PATH_ESCAPE.search(path):
        return None
    host, port = ascii_lower(authority[1]), None
    if authority[2] is not None:
        port = decimal(authority[2])
        if port > PORT_MAX:
            return None
    if host.startswith("["):
        host = host[1:-1]
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return None
    else:
        labels = host.split(".")
        if len(host) > HOST_MAX or not all(HOST_LABEL.fullmatch(label) for label in labels):
            return None
        if NUMERIC_LABEL.fullmatch(labels[-1]) and not IPV4.fullmatch(host):
            return None  # a host ending in a number is an IPv4 address; read only in its one canonical spelling
    return ascii_lower(url[1]), host, port, path


def _private_host(host: str) -> bool:
    """True for loopback, link-local, private and reserved hosts. ``host`` is one ``url_parts`` gave, so an address is
    written in its one spelling (a dotted quad or an IPv6 literal); the other numeric notations a resolver reads are
    refused before this is asked. A DNS name that resolves to a private address is not visible here: the egress layer re-checks
    the address it actually connects to."""
    if host in ("localhost", "localhost.localdomain") or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
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


def _check_url_pattern(c: dict[str, Any], v: Any) -> bool:
    parts = url_parts(v)
    if parts is None:
        return False
    scheme, host, _, path = parts
    prefix = c.get("pathPrefix", "/").rstrip("/")
    return (scheme in c["schemes"] and _host_ok(host, c["hosts"])
            and (not prefix or path == prefix or path.startswith(prefix + "/")))


def _check_url_safe(c: dict[str, Any], v: Any) -> bool:
    parts = url_parts(v)
    if parts is None:
        return False
    scheme, host, _, _ = parts
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
        return all(_member(item, v) for item in c["values"])
    return all(_member(item, c["values"]) for item in v)


_CHECKS: dict[str, Callable[[dict[str, Any], Any], bool]] = {
    "wildcard": lambda c, v: True,
    "exact": lambda c, v: same(v, c["value"]) and type(v) is type(c["value"]),
    "one_of": lambda c, v: any(same(v, x) and type(v) is type(x) for x in c["values"]),
    "not_one_of": lambda c, v: _keys([v]) is not None and not _member(v, c["values"]),
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


#: Per type, in check order, each member's shape: ``(member, kind, required)``. A kind is ``list``, ``number``
#: (an int or a float, never a bool), ``str``, ``strlist`` (a list of strings), ``bool`` or ``nonempty`` (a non-empty
#: list). The TypeScript verifier holds the same table (``MEMBER_SHAPES`` in verify.ts), so both twins refuse one
#: constraint with one code.
_SHAPES: dict[str, tuple[tuple[str, str, bool], ...]] = {
    "one_of": (("values", "list", True),), "not_one_of": (("values", "list", True),),
    "range": (("min", "number", False), ("max", "number", False)), "pattern": (("pattern", "str", True),),
    "regex": (("regex", "str", True),), "cidr": (("network", "str", True),),
    "url_pattern": (("schemes", "strlist", True), ("hosts", "strlist", True), ("pathPrefix", "str", False)),
    "url_safe": (("schemes", "strlist", False), ("hosts", "strlist", False), ("denyPrivate", "bool", False)),
    "subpath": (("root", "str", True),), "shlex": (("allow", "list", True),), "contains": (("values", "list", True),),
    "subset": (("values", "list", True),), "all": (("of", "nonempty", True),), "any": (("of", "nonempty", True),),
    "cel": (("expr", "str", True),),
}


def _shape_ok(kind: str, value: Any) -> bool:
    if kind == "number":
        return _number(value)
    if kind == "str":
        return isinstance(value, str)
    if kind == "bool":
        return isinstance(value, bool)
    if kind == "strlist":
        return isinstance(value, list) and all(isinstance(x, str) for x in value)
    return isinstance(value, list) and (kind == "list" or bool(value))


def problem(c: Any) -> str | None:
    """None when ``c`` is a well-formed constraint; otherwise the first defect, as a code both verifiers report:
    ``constraint_unknown``, ``constraint_member_missing:<type>.<member>``, ``constraint_range_unbounded``,
    ``constraint_member_invalid:<type>.<member>``, ``constraint_regex_invalid``, ``constraint_cidr_invalid`` or a
    ``celexpr.syntax_problem`` code. A nested constraint reports its own code."""
    if not isinstance(c, dict) or not isinstance(c.get("type"), str) or c["type"] not in TYPES:
        return "constraint_unknown"
    kind = c["type"]
    missing = [k for k in _REQUIRED.get(kind, ()) if k not in c]
    if missing:
        return f"constraint_member_missing:{kind}.{missing[0]}"
    if kind == "range" and not ({"min", "max"} & c.keys()):
        return "constraint_range_unbounded"
    for member, shape, required in _SHAPES.get(kind, ()):
        if (required or member in c) and not _shape_ok(shape, c[member]):
            return f"constraint_member_invalid:{kind}.{member}"
    for nested in c["of"] if kind in ("all", "any") else [c["of"]] if kind == "not" else []:
        found = problem(nested)
        if found:
            return found
    if kind == "regex":
        try:
            re.compile(c["regex"])
        except Exception:  # noqa: BLE001 - re.error is not a ValueError; any refusal to compile is the one defect
            return "constraint_regex_invalid"
    if kind == "cidr":
        try:
            ipaddress.ip_network(c["network"])
        except ValueError:
            return "constraint_cidr_invalid"
    if kind == "cel":
        return celexpr.syntax_problem(c["expr"])
    return None


def validate(c: Any) -> dict[str, Any]:
    """The constraint, when well formed; ConstraintError naming the ``problem`` code otherwise."""
    found = problem(c)
    if found:
        raise ConstraintError(found)
    return c


def check(c: dict[str, Any], value: Any) -> bool:
    """Whether ``value`` satisfies constraint ``c``."""
    validate(c)
    return _CHECKS[c["type"]](c, value)


def _contained(inner: list[Any], outer: list[Any]) -> bool:
    """Whether every value of ``inner`` is a value of ``outer``, by value key."""
    inner_keys, outer_keys = _keys(inner), _keys(outer)
    return inner_keys is not None and outer_keys is not None and inner_keys <= outer_keys


def _same_type_narrows(child: dict[str, Any], parent: dict[str, Any]) -> bool:
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
        return _contained(child["allow" if kind == "shlex" else "values"], parent["allow" if kind == "shlex" else "values"])
    if kind in ("contains", "not_one_of"):
        return _contained(parent["values"], child["values"])
    return same(child, parent)  # regex, not, cel: only an identical constraint is provably no wider


def narrows(child: dict[str, Any], parent: dict[str, Any]) -> bool:
    """True only when every value ``child`` admits is provably admitted by ``parent``."""
    validate(child)
    validate(parent)
    if parent["type"] == "wildcard" or same(child, parent):
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
