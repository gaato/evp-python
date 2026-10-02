"""Structured Field Values for HTTP (RFC 9651): parsing and serialisation.

HTTP Message Signatures (RFC 9421) are built from Structured Fields, and the
signature base contains a re-serialisation of what was parsed, so both halves
must follow the RFC exactly.  Every parse failure raises :class:`SFError`; per
RFC 9651 the whole field is then ignored, never partially used.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Decimal
from typing import TypeAlias

__all__ = [
    "Date",
    "DisplayString",
    "InnerList",
    "Item",
    "SFError",
    "Token",
    "parse_dictionary",
    "parse_item",
    "parse_list",
    "serialize_dictionary",
    "serialize_inner_list",
    "serialize_item",
    "serialize_list",
]


class SFError(ValueError):
    """The field value is not a valid Structured Field."""


class Token(str):
    """An sf-token, as opposed to an sf-string."""

    __slots__ = ()


class DisplayString(str):
    """An sf-displaystring (Unicode text)."""

    __slots__ = ()


class Date(int):
    """An sf-date (seconds since the epoch)."""

    __slots__ = ()


# TODO(py3.12): back to a ``type`` statement once 3.11 support is dropped.
BareItem: TypeAlias = int | Decimal | str | bytes | bool
Parameters: TypeAlias = dict[str, BareItem]


@dataclass(frozen=True, slots=True)
class Item:
    value: BareItem
    params: Parameters = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class InnerList:
    items: tuple[Item, ...]
    params: Parameters = field(default_factory=dict)


Member: TypeAlias = Item | InnerList

_TOKEN_START = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz*")
_BASE64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_INTEGER_MAX = 999_999_999_999_999
_DECIMAL_INTEGER_MAX = 999_999_999_999
_TOKEN_RE = re.compile(r"[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*")
_KEY_RE = re.compile(r"[a-z*][a-z0-9_\-.*]*")


class _Parser:
    def __init__(self, lines: str | Iterable[str]) -> None:
        text = lines if isinstance(lines, str) else ", ".join(lines)
        if not text.isascii():
            raise SFError("field value is not ASCII")
        self.s = text.lstrip(" ")
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
        while self.peek() in (" ", "\t") and self.peek():
            self.i += 1

    def done(self) -> bool:
        return self.i >= len(self.s)

    def finish(self) -> None:
        self.skip_sp()
        if not self.done():
            raise SFError(f"unexpected {self.peek()!r} at {self.i}")

    def comma_or_end(self) -> bool:
        """After a member: ``True`` to continue, ``False`` at the end of the field."""
        self.skip_ows()
        if self.done():
            return False
        if self.take() != ",":
            raise SFError(f"expected ',' at {self.i - 1}")
        self.skip_ows()
        if self.done():
            raise SFError("trailing comma")
        return True

    # --- RFC 9651 section 4.2 ---

    def list_(self) -> list[Member]:
        members: list[Member] = []
        while not self.done():
            members.append(self.member())
            if not self.comma_or_end():
                break
        return members

    def dictionary(self) -> dict[str, Member]:
        members: dict[str, Member] = {}
        while not self.done():
            key = self.key()
            if self.peek() == "=":
                self.i += 1
                member = self.member()
            else:
                member = Item(True, self.parameters())
            # A repeated key keeps its first position and takes its last value.
            members[key] = member
            if not self.comma_or_end():
                break
        return members

    def member(self) -> Member:
        return self.inner_list() if self.peek() == "(" else self.item()

    def inner_list(self) -> InnerList:
        self.i += 1  # "("
        items: list[Item] = []
        while not self.done():
            self.skip_sp()
            if self.peek() == ")":
                self.i += 1
                return InnerList(tuple(items), self.parameters())
            items.append(self.item())
            if self.peek() not in (" ", ")"):
                raise SFError(f"expected ' ' or ')' at {self.i}")
        raise SFError("unterminated inner list")

    def item(self) -> Item:
        return Item(self.bare_item(), self.parameters())

    def bare_item(self) -> BareItem:
        c = self.peek()
        if c == "-" or c.isdigit():
            return self.number()
        if c == '"':
            return self.string()
        if c in _TOKEN_START and c:
            return self.token()
        if c == ":":
            return self.byte_sequence()
        if c == "?":
            return self.boolean()
        if c == "@":
            self.i += 1
            value = self.number()
            if not isinstance(value, int):
                raise SFError("date is not an integer")
            return Date(value)
        if c == "%":
            return self.display_string()
        raise SFError(f"unexpected {c!r} at {self.i}" if c else "missing item")

    def parameters(self) -> Parameters:
        params: Parameters = {}
        while self.peek() == ";":
            self.i += 1
            self.skip_sp()
            key = self.key()
            value: BareItem = True
            if self.peek() == "=":
                self.i += 1
                value = self.bare_item()
            params[key] = value
        return params

    def key(self) -> str:
        if (m := _KEY_RE.match(self.s, self.i)) is None:
            raise SFError(f"invalid key at {self.i}")
        self.i = m.end()
        return m.group()

    def number(self) -> int | Decimal:
        start = self.i
        if self.peek() == "-":
            self.i += 1
        if not self.peek().isdigit() or not self.peek():
            raise SFError(f"expected a digit at {self.i}")
        while self.peek() and (self.peek().isdigit() or self.peek() == "."):
            self.i += 1
        text = self.s[start : self.i]
        digits = text.lstrip("-")
        if "." not in digits:
            if len(digits) > 15:
                raise SFError("integer too long")
            return int(text)
        whole, _, frac = digits.partition(".")
        if "." in frac or len(whole) > 12 or not 1 <= len(frac) <= 3:
            raise SFError("invalid decimal")
        return Decimal(text)

    def string(self) -> str:
        self.i += 1  # '"'
        out: list[str] = []
        while not self.done():
            c = self.take()
            if c == "\\":
                if (n := self.take()) not in ('"', "\\"):
                    raise SFError("invalid escape in string")
                out.append(n)
            elif c == '"':
                return "".join(out)
            elif not " " <= c <= "~":
                raise SFError("invalid character in string")
            else:
                out.append(c)
        raise SFError("unterminated string")

    def token(self) -> Token:
        m = _TOKEN_RE.match(self.s, self.i)
        assert m is not None
        self.i = m.end()
        return Token(m.group())

    def byte_sequence(self) -> bytes:
        end = self.s.find(":", self.i + 1)
        if end < 0:
            raise SFError("unterminated byte sequence")
        b64 = self.s[self.i + 1 : end]
        self.i = end + 1
        if not set(b64) <= _BASE64_CHARS:
            raise SFError("invalid base64 in byte sequence")
        try:
            # Senders must pad; RFC 9651 lets parsers accept unpadded input.
            return base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=True)
        except binascii.Error as exc:
            raise SFError("invalid base64 in byte sequence") from exc

    def boolean(self) -> bool:
        self.i += 1  # "?"
        c = self.take()
        if c not in ("0", "1"):
            raise SFError("invalid boolean")
        return c == "1"

    def display_string(self) -> DisplayString:
        self.i += 1  # "%"
        if self.take() != '"':
            raise SFError("expected '\"' after '%'")
        out = bytearray()
        while not self.done():
            c = self.take()
            if c == "%":
                hex2 = self.s[self.i : self.i + 2]
                if len(hex2) != 2 or not set(hex2) <= set("0123456789abcdef"):
                    raise SFError("invalid percent-encoding in display string")
                out.append(int(hex2, 16))
                self.i += 2
            elif c == '"':
                try:
                    return DisplayString(out.decode("utf-8"))
                except UnicodeDecodeError as exc:
                    raise SFError("display string is not UTF-8") from exc
            elif not " " <= c <= "~":
                raise SFError("invalid character in display string")
            else:
                out.append(ord(c))
        raise SFError("unterminated display string")


def parse_list(lines: str | Iterable[str]) -> list[Member]:
    p = _Parser(lines)
    members = p.list_()
    p.finish()
    return members


def parse_dictionary(lines: str | Iterable[str]) -> dict[str, Member]:
    p = _Parser(lines)
    members = p.dictionary()
    p.finish()
    return members


def parse_item(lines: str | Iterable[str]) -> Item:
    p = _Parser(lines)
    item = p.item()
    p.finish()
    return item


# --- RFC 9651 section 4.1 ---


def serialize_list(members: Iterable[Member]) -> str:
    return ", ".join(_serialize_member(m) for m in members)


def serialize_dictionary(members: dict[str, Member]) -> str:
    out: list[str] = []
    for key, member in members.items():
        if isinstance(member, Item) and member.value is True:
            out.append(_serialize_key(key) + _serialize_params(member.params))
        else:
            out.append(f"{_serialize_key(key)}={_serialize_member(member)}")
    return ", ".join(out)


def serialize_inner_list(inner: InnerList) -> str:
    items = " ".join(serialize_item(i) for i in inner.items)
    return f"({items}){_serialize_params(inner.params)}"


def serialize_item(item: Item) -> str:
    return _serialize_bare(item.value) + _serialize_params(item.params)


def _serialize_member(member: Member) -> str:
    return serialize_inner_list(member) if isinstance(member, InnerList) else serialize_item(member)


def _serialize_params(params: Parameters) -> str:
    return "".join(
        ";" + _serialize_key(key) + ("" if value is True else "=" + _serialize_bare(value))
        for key, value in params.items()
    )


def _serialize_key(key: str) -> str:
    if _KEY_RE.fullmatch(key) is None:
        raise SFError(f"invalid key {key!r}")
    return key


def _serialize_bare(value: BareItem) -> str:
    if isinstance(value, bool):
        return "?1" if value else "?0"
    if isinstance(value, Date):
        return "@" + _serialize_integer(value)
    if isinstance(value, int):
        return _serialize_integer(value)
    if isinstance(value, Decimal):
        return _serialize_decimal(value)
    if isinstance(value, Token):
        if _TOKEN_RE.fullmatch(value) is None:
            raise SFError(f"invalid token {value!r}")
        return str(value)
    if isinstance(value, DisplayString):
        encoded = "".join(
            f"%{b:02x}" if b in (0x25, 0x22) or not 0x20 <= b <= 0x7E else chr(b)
            for b in value.encode("utf-8")
        )
        return f'%"{encoded}"'
    if isinstance(value, str):
        if not all(" " <= c <= "~" for c in value):
            raise SFError("string contains characters outside printable ASCII")
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(value, bytes):
        return ":" + base64.b64encode(value).decode("ascii") + ":"
    raise SFError(f"cannot serialise {type(value).__name__}")


def _serialize_integer(value: int) -> str:
    if not -_INTEGER_MAX <= value <= _INTEGER_MAX:
        raise SFError("integer out of range")
    return str(int(value))


def _serialize_decimal(value: Decimal) -> str:
    rounded = value.quantize(Decimal("0.001"), rounding=ROUND_HALF_EVEN)
    whole, _, frac = f"{abs(rounded):f}".partition(".")
    if len(whole) > 12 or int(whole) > _DECIMAL_INTEGER_MAX:
        raise SFError("decimal out of range")
    frac = frac.rstrip("0") or "0"
    return ("-" if rounded < 0 else "") + f"{whole}.{frac}"
