"""Generated inputs for the URL constraint differential (``test_constraint_url.py``), from ``grammar/constraint-url.json``.

Every value is one a grant's ``url_pattern`` or ``url_safe`` constraint may be asked about. The families: each
production's accepted and refused texts from the grammar file; every combination of a small set of schemes,
separators, userinfo, hosts, ports, paths and query or fragment texts that each production treats differently; each
code point of a troublesome set inserted at every position of a few accepted URLs; and values of other JSON types.
The set is fixed by its seed, so a failing value is reproduced by its index.
"""

from __future__ import annotations

import itertools
import json
import random
from pathlib import Path
from typing import Any

GRAMMAR = Path(__file__).resolve().parents[1] / "grammar" / "constraint-url.json"

SCHEMES = ("https", "http", "HTTPS", "Https", "ftp", "h", "", "1http", "ht+tp", "ht-tp.x")
SEPARATORS = ("://", ":/", ":", ":///", "\\\\", ":\\\\", "//", ":/\\")
USERINFO = ("", "@", "u@", ":@", "u:p@", "%40@")
HOSTS = (
    "api.example.com", "a.example.com", "example.com", "API.Example.COM", "localhost", "LOCALHOST", "LOCALHOST.",
    "localhost.localdomain", "x.localhost", "x.LocalHost", "127.0.0.1", "127.1", "0x7f.0.0.1", "0177.0.0.1",
    "2130706433", "10.1", "0", "8.8.8.8", "256.1.1.1", "1.2.3.04", "01.2.3.4", "1.2.3.4.5", "1.2.3", "example.123",
    "0x", "0X1.0.0.1", "1.2.3.0x4", "123.example.com", "a.0x", "[::1]", "[2001:db8::1]", "[::ffff:8.8.8.8]",
    "[::ffff:127.0.0.1]", "[fe80::1]", "[2001:4860:4860::8888]", "[::]", "[1::2::3]", "[::g]", "[]", "[1.2.3.4]",
    "[::FFFF:8.8.8.8]", "[0:0:0:0:0:0:0:1]", "[::1:2:3:4:5:6:7:8]", "[::1%25eth0]", "[v1.x]", "api.example.com.",
    ".example.com", "a..example.com", "a-.example.com", "-a.example.com", "a" * 63 + ".example.com",
    "a" * 64 + ".example.com", ".".join(["a" * 63] * 3) + "." + "a" * 61, ".".join(["a" * 63] * 3) + "." + "a" * 62,
    "api%2eexample.com", "api.example.com%2f.evil.example", "xn--bcher-kva.example", "a_b.example.com", "",
    "api.example.com\\@evil.example", "evil.example#@api.example.com",
)  # fmt: skip
PORTS = ("", ":", ":0", ":00", ":1", ":443", ":0443", ":8443", ":65535", ":65536", ":99999", ":100000",
         ":" + "0" * 5000 + "443", ":+1", ":44a", ":4_43", ":-1")  # fmt: skip
PATHS = ("", "/", "/v1", "/v1/", "/v1/x", "/v1/../admin", "/v1/./x", "/v1//x", "//v1/x", "/v1/%2e%2e/admin",
         "/v1/%2E/x", "/v1%2fx", "/v1/%252e", "/v1/%41", "/v1/%zz", "/v1/%4", "/v1/..", "/v1/.", "/./v1", "/v1/x..y",
         "/v1/...", "/v1\\x", "/v1x", "/V1/x", "/v1/x/", "/..", "/.")  # fmt: skip
RESTS = ("", "?", "?q=1", "#f", "?q=/../#x", "?@evil", "#/../admin", "?a#b#c")
#: Characters that one platform parser strips, folds, maps or treats as a separator and another does not.
ODD = ("\x00", "\t", "\n", "\r", " ", "\x7f", "\\", "%", "@", "#", "?", "[", "]", ":", "\u00a0", "\u0130", "\u212a",
       "\u3002", "\uff0e", "\uff0f", "\u2028", "\ufeff", "\u200b", "\ud800", "\U0001f600", "\u00e9", "\u0131")  # fmt: skip
OTHER_TYPES: tuple[Any, ...] = (None, True, False, 0, 1, 1.5, -1, [], ["https://api.example.com/v1/x"], {},
                                {"url": "https://api.example.com/v1/x"})  # fmt: skip
#: The constraints each value is checked against: strict and loose, so a parse difference shows in some verdict.
CONSTRAINTS: tuple[dict[str, Any], ...] = (
    {"type": "url_pattern", "schemes": ["https"], "hosts": ["api.example.com", "*.example.com"], "pathPrefix": "/v1"},
    {"type": "url_pattern", "schemes": ["http", "https"], "hosts": ["*"]},
    {"type": "url_pattern", "schemes": ["http", "https"], "hosts": ["*"], "pathPrefix": "/v1/"},
    {"type": "url_pattern", "schemes": ["https"], "hosts": ["API.EXAMPLE.COM"]},
    {"type": "url_safe"},
    {"type": "url_safe", "schemes": ["http", "https"]},
    {"type": "url_safe", "schemes": ["http", "https", "ftp", "h"], "denyPrivate": False},
    {"type": "url_safe", "schemes": ["http", "https"], "hosts": ["*.example.com", "localhost"]},
)
SEED = 20261127
RANDOM_COMBINATIONS = 12000
#: Parts the grammar accepts, so a random combination of them is read by both readers and the parts are compared,
#: not only two refusals.
GOOD_SCHEMES = ("https", "http", "HTTPS", "Http", "ftp")
GOOD_HOSTS = ("api.example.com", "a.example.com", "example.com", "API.Example.COM", "localhost", "x.localhost",
              "127.0.0.1", "8.8.8.8", "10.0.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "[::1]",
              "[2001:db8::1]", "[::ffff:8.8.8.8]", "[::ffff:127.0.0.1]", "[fe80::1]", "[2001:4860:4860::8888]",
              "[::]", "[0:0:0:0:0:0:0:1]", "123.example.com", "xn--bcher-kva.example", "a-b.example.com")  # fmt: skip
GOOD_PORTS = ("", ":1", ":80", ":443", ":8443", ":65535")
GOOD_PATHS = ("", "/", "/v1", "/v1/", "/v1/x", "/v1/x/", "/v1x", "/V1/x", "/v1/x..y", "/v1/...", "/v1/%41", "/api/v1",
              "/v1/a;b=c", "/v1/~u/!$&'()*+,=:@")  # fmt: skip
GOOD_RESTS = ("", "?", "?q=1", "#f", "?q=/../#x", "?@evil", "#/../admin")
GOOD_COMBINATIONS = 4000


def grammar() -> dict[str, Any]:
    return json.loads(GRAMMAR.read_text())


def _string_values() -> list[str]:
    doc = grammar()
    out: list[str] = [case[0] for case in doc["cases"]["accept"]] + list(doc["cases"]["refuse"])
    base = ("https://", "api.example.com", "", "/v1/x", "")
    axes = (SCHEMES, SEPARATORS, USERINFO, HOSTS, PORTS, PATHS, RESTS)
    # one axis moved at a time from an accepted URL, then every pair of host and port, and of host and path
    for axis, values in enumerate(axes):
        for value in values:
            parts = ["https", "://", "", "api.example.com", "", "/v1/x", ""]
            parts[axis] = value
            out.append("".join(parts))
    for host, port in itertools.product(HOSTS, PORTS):
        out.append(f"http://{host}{port}/v1/x")
    for host, path in itertools.product(HOSTS, PATHS):
        out.append(f"https://{host}{path}")
    rng = random.Random(SEED)
    for _ in range(RANDOM_COMBINATIONS):
        out.append("".join(rng.choice(axis) for axis in axes))
    for _ in range(GOOD_COMBINATIONS):
        out.append("".join((rng.choice(GOOD_SCHEMES), "://", rng.choice(GOOD_HOSTS), rng.choice(GOOD_PORTS),
                            rng.choice(GOOD_PATHS), rng.choice(GOOD_RESTS))))  # fmt: skip
    for url in ("https://api.example.com/v1/x?q=1", "http://[::1]:8443/", "https://a.example.com:443/v1/", base[0] + base[1]):
        for position in range(len(url) + 1):
            for ch in ODD:
                out.append(url[:position] + ch + url[position:])
    return list(dict.fromkeys(out))


def values() -> list[Any]:
    """Every generated value, strings first, then values of other JSON types."""
    return [*_string_values(), *OTHER_TYPES]
