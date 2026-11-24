"""The host every identifier we publish is written under, and the hosts read as ours.

An identifier here is a URI we define and a record carries: a ``predicateType``, a ``contractId``,
a ``claim_type``, a schema or verifier id, a registry key. Each is written as
``https://<IDENTIFIER_HOST>/<path>`` and built with :func:`identifier`, so moving the host is a
change to one line.

A signed record cannot be edited without breaking its signature, so every record already issued
keeps the identifiers it was signed with, under ``https://probityai.github.io/``, forever. From the
release that changes ``IDENTIFIER_HOST``, new records carry ``https://probityai.org/``. Both hosts
are ours: GitHub serves the old one for the probityai organisation and forwards every path on it
to the same path on the new one, which is verified for that organisation. So the two spellings
name one type, and a verifier that accepted only one would reject either every record already
issued or every record issued from then on. Accepting both widens nothing an attacker controls:
an identifier is a label, not a credential, and trust comes from the signature and the key, which
this module does not touch. The match is byte-exact on the scheme and the host; no other spelling
is recognised.

So a reader compares ``canonical_identifier(<value from the record>)`` with its constant, or calls
:func:`same_identifier`, and reports the record's own bytes. Signed bytes are never rewritten: a
DSSE pre-authentication encoding is computed over the payload as received.

This file has no imports and is copied byte for byte into the packages that do not depend on
agent-evidence-verify; each copy has a test that it equals this file.
"""

IDENTIFIER_HOST = "probityai.github.io"
RECOGNISED_HOSTS = ("probityai.github.io", "probityai.org")

_WRITTEN = "https://" + IDENTIFIER_HOST + "/"
_READ = tuple("https://" + host + "/" for host in RECOGNISED_HOSTS)


def identifier(path: str) -> str:
    """``https://<IDENTIFIER_HOST>/<path>``: the identifier this release writes for ``path``."""
    return _WRITTEN + path


def canonical_identifier(value):
    """``value`` with a recognised host replaced by ``IDENTIFIER_HOST``; anything else unchanged.

    Only a string that starts with exactly ``https://<host>/`` for a host in ``RECOGNISED_HOSTS``
    is rewritten, and only that prefix. ``http://``, ``www.``, a port, a trailing dot, upper case,
    userinfo and every longer host keep their bytes, so they fail every comparison they fail
    today. A value that is not a string is returned as it is.
    """
    if isinstance(value, str):
        for prefix in _READ:
            if value.startswith(prefix):
                return _WRITTEN + value[len(prefix):]
    return value


def same_identifier(a, b) -> bool:
    """Whether ``a`` and ``b`` name the same identifier under the recognised hosts."""
    return canonical_identifier(a) == canonical_identifier(b)
