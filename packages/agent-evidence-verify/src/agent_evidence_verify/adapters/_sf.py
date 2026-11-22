"""Structured Field Values for HTTP (RFC 8941): the subset HTTP Message Signatures need, read strictly.

Dictionaries, Items and Inner Lists; bare items of type String, Token, Integer, Decimal, Byte
Sequence and Boolean; parameters on items and inner lists. Dates and Display Strings (RFC 9651)
are not read. A parse error raises :class:`SFError`.

Three rules go beyond RFC 8941, because a signature verifier must not let a repeated name or an
unusual spelling decide which value it read. A repeated Dictionary key and a repeated parameter
name are refused (RFC 8941 keeps the last). A number is read only from the digits 0 to 9 (the
regular-expression class for digits and ``str.isdigit`` also accept other scripts' digits). A Byte
Sequence is read only in the one spelling an encoder writes (``strictb64.std``).

Serialisation is the strict form of RFC 8941 section 4.1, which the signature base requires
(RFC 9421 sections 2.1.2 and 2.5), so a value re-serialised here is, byte for byte, what another
conformant implementation writes.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Decimal

from .. import strictb64


class SFError(ValueError):
    """The field is not a valid Structured Field of the expected type."""


class Token(str):
    """A Token bare item (RFC 8941 section 3.3.4), kept apart from Strings."""

    __slots__ = ()


BareItem = str | Token | int | Decimal | bytes | bool


@dataclass(frozen=True, slots=True)
class Item:
    value: BareItem
    params: dict[str, BareItem] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class InnerList:
    items: list[Item]
    params: dict[str, BareItem] = field(default_factory=dict)


Member = Item | InnerList

_TOKEN_START = re.compile(r"[A-Za-z*]")
_TOKEN_CHARS = re.compile(r"[A-Za-z0-9!#$%&'*+\-.^_`|~:/]")
_KEY_START = re.compile(r"[a-z*]")
_KEY_CHARS = re.compile(r"[a-z0-9_\-.*]")
_NUMBER = re.compile(r"-?([0-9]+)(\.[0-9]+)?")
_DIGITS = "0123456789"


class _Parser:
    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def take(self) -> str:
        c = self.peek()
        self.i += 1
        return c

    def skip_sp(self) -> None:
        while self.peek() == " ":
            self.i += 1

    def skip_ows(self) -> None:
        while self.peek() and self.peek() in " \t":
            self.i += 1

    def done(self) -> bool:
        return self.i >= len(self.s)

    def fail(self, why: str) -> SFError:
        return SFError(f"{why} at offset {self.i} in {self.s!r}")

    # -- RFC 8941 section 4.2 -------------------------------------------
    def dictionary(self) -> dict[str, Member]:
        out: dict[str, Member] = {}
        while not self.done():
            key = self.key()
            if key in out:
                raise self.fail(f"repeated dictionary key {key!r}")
            if self.peek() == "=":
                self.take()
                out[key] = self.item_or_inner_list()
            else:
                out[key] = Item(True, self.parameters())
            self.skip_ows()
            if self.done():
                return out
            if self.take() != ",":
                raise self.fail("expected ','")
            self.skip_ows()
            if self.done():
                raise self.fail("trailing comma")
        return out

    def item_or_inner_list(self) -> Member:
        if self.peek() == "(":
            return self.inner_list()
        return self.item()

    def inner_list(self) -> InnerList:
        if self.take() != "(":
            raise self.fail("expected '('")
        items: list[Item] = []
        while not self.done():
            self.skip_sp()
            if self.peek() == ")":
                self.take()
                return InnerList(items, self.parameters())
            items.append(self.item())
            if self.peek() not in (" ", ")"):
                raise self.fail("expected space or ')' in inner list")
        raise self.fail("unterminated inner list")

    def item(self) -> Item:
        value = self.bare_item()
        return Item(value, self.parameters())

    def parameters(self) -> dict[str, BareItem]:
        params: dict[str, BareItem] = {}
        while self.peek() == ";":
            self.take()
            self.skip_sp()
            name = self.key()
            if name in params:
                raise self.fail(f"repeated parameter {name!r}")
            if self.peek() == "=":
                self.take()
                params[name] = self.bare_item()
            else:
                params[name] = True
        return params

    def key(self) -> str:
        if not _KEY_START.match(self.peek() or "\0"):
            raise self.fail("expected a key")
        start = self.i
        while not self.done() and _KEY_CHARS.match(self.peek()):
            self.i += 1
        return self.s[start : self.i]

    def bare_item(self) -> BareItem:
        c = self.peek()
        if c == "":
            raise self.fail("expected a bare item")
        if c == "-" or c in _DIGITS:
            return self.number()
        if c == '"':
            return self.string()
        if _TOKEN_START.match(c):
            return self.token()
        if c == ":":
            return self.byte_sequence()
        if c == "?":
            return self.boolean()
        raise self.fail("unexpected character")

    def number(self) -> int | Decimal:
        m = _NUMBER.match(self.s, self.i)
        if not m:
            raise self.fail("expected a number")
        text = m.group(0)
        self.i = m.end()
        if m.group(2) is None:
            if len(m.group(1)) > 15:
                raise self.fail("integer too long")
            return int(text)
        if len(m.group(1)) > 12 or len(m.group(2)) - 1 > 3:
            raise self.fail("decimal too long")
        return Decimal(text)

    def string(self) -> str:
        if self.take() != '"':
            raise self.fail("expected '\"'")
        out = []
        while not self.done():
            c = self.take()
            if c == "\\":
                n = self.take()
                if n not in ('"', "\\"):
                    raise self.fail("bad escape in string")
                out.append(n)
            elif c == '"':
                return "".join(out)
            elif not (0x20 <= ord(c) <= 0x7E):
                raise self.fail("non-ASCII or control character in string")
            else:
                out.append(c)
        raise self.fail("unterminated string")

    def token(self) -> Token:
        start = self.i
        self.i += 1
        while not self.done() and _TOKEN_CHARS.match(self.peek()):
            self.i += 1
        return Token(self.s[start : self.i])

    def byte_sequence(self) -> bytes:
        if self.take() != ":":
            raise self.fail("expected ':'")
        end = self.s.find(":", self.i)
        if end < 0:
            raise self.fail("unterminated byte sequence")
        raw = self.s[self.i : end]
        self.i = end + 1
        try:
            return strictb64.std(raw)
        except (binascii.Error, ValueError) as error:
            raise self.fail(f"bad base64: {error}") from error

    def boolean(self) -> bool:
        if self.take() != "?":
            raise self.fail("expected '?'")
        c = self.take()
        if c == "1":
            return True
        if c == "0":
            return False
        raise self.fail("bad boolean")


def parse_dictionary(text: str) -> dict[str, Member]:
    """Parse a Dictionary field value. Several field lines are combined by the caller with
    ``", "`` before parsing, as RFC 8941 section 4.2 requires."""
    p = _Parser(text.strip(" \t"))
    out = p.dictionary()
    if not p.done():
        raise p.fail("trailing characters")
    return out


def parse_item(text: str) -> Item:
    p = _Parser(text.strip(" \t"))
    item = p.item()
    if not p.done():
        raise p.fail("trailing characters")
    return item


# -- RFC 8941 section 4.1, strict serialisation -----------------------------


def serialize_bare_item(value: BareItem) -> str:
    if isinstance(value, bool):
        return "?1" if value else "?0"
    if isinstance(value, Token):
        return str(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, Decimal):
        q = value.quantize(Decimal("0.001"), rounding=ROUND_HALF_EVEN)
        text = format(q, "f")
        whole, _, frac = text.partition(".")
        frac = frac.rstrip("0") or "0"
        return f"{whole}.{frac}"
    if isinstance(value, bytes):
        return ":" + base64.b64encode(value).decode("ascii") + ":"
    if isinstance(value, str):
        for c in value:
            if not (0x20 <= ord(c) <= 0x7E):
                raise SFError("string contains a non-ASCII or control character")
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    raise SFError(f"cannot serialise {type(value).__name__}")


def serialize_params(params: dict[str, BareItem]) -> str:
    out = []
    for name, value in params.items():
        if value is True:
            out.append(f";{name}")
        else:
            out.append(f";{name}={serialize_bare_item(value)}")
    return "".join(out)


def serialize_item(item: Item) -> str:
    return serialize_bare_item(item.value) + serialize_params(item.params)


def serialize_inner_list(inner: InnerList) -> str:
    return "(" + " ".join(serialize_item(i) for i in inner.items) + ")" + serialize_params(inner.params)


def serialize_member(member: Member) -> str:
    """A Dictionary member's value with its parameters, without the key (RFC 9421 section 2.1.2)."""
    if isinstance(member, InnerList):
        return serialize_inner_list(member)
    return serialize_item(member)
