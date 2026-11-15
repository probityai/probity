#!/usr/bin/env python3
"""Fail a README whose remote image does not load as an image.

A package README is the PyPI long description, and a badge URL that answers 404
(PePy before it has data for a name) or a JSON error body shows as a broken image
on the page. This check fetches every absolute http(s) image in each README given
(Markdown images and <img src>) and fails on a non-200 status or a content type that
is not image/*. A fetch that cannot complete (no network, timeout) fails too: an
unread image is not a passing image.

An image this repository serves from its own default branch
(https://raw.githubusercontent.com/probityai/probity/main/<path>) is read from the
checkout instead: a pull request that adds a badge and the README line naming it
would otherwise fail until it merges, and after the merge the checkout's file is
exactly what the URL serves. The file must exist and start like an image.

usage: readme-image-check.py README.md [README.md ...]
Exit 0 when every image loads, 1 when one does not.
"""

from __future__ import annotations

import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

MD_IMAGE = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+)")
IMG_SRC = re.compile(r"""<img\b[^>]*?\bsrc=["'](https?://[^"']+)["']""", re.IGNORECASE)
UA = "probityai-readme-image-check"
OWN_RAW = re.compile(r"^https://raw\.githubusercontent\.com/probityai/probity/main/(?P<path>[^?#]+)$")
ROOT = Path(__file__).resolve().parent.parent
IMAGE_MAGIC = (b"<svg", b"<?xml", b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a", b"\xff\xd8\xff", b"RIFF")


def image_urls(text: str) -> list[str]:
    return list(dict.fromkeys(MD_IMAGE.findall(text) + IMG_SRC.findall(text)))


def probe(url: str) -> tuple[int, str]:
    """(status, content type) of a GET; status 0 when no answer came."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", "") if exc.headers else ""
    except OSError:
        return 0, ""


def local_image(root: Path, rel: str) -> str | None:
    """None when root/rel is an image file in the checkout, else why not."""
    path = (root / rel).resolve()
    if root.resolve() not in path.parents or not path.is_file():
        return "names a file this checkout does not hold"
    head = path.read_bytes()[:64].lstrip()
    if not head.startswith(IMAGE_MAGIC):
        return "names a checkout file that is not an image"
    return None


def check(readme: Path, fetch=probe, root: Path = ROOT) -> list[str]:
    failures = []
    for url in image_urls(readme.read_text(encoding="utf-8")):
        own = OWN_RAW.match(url)
        if own is not None:
            why = local_image(root, own.group("path"))
            if why is not None:
                failures.append(f"{readme}: image {url} {why}")
            continue
        status, ctype = fetch(url)
        if status != 200:
            failures.append(f"{readme}: image {url} answered {status or 'nothing'}, not 200")
        elif not ctype.lower().startswith("image/"):
            failures.append(f"{readme}: image {url} is {ctype or 'untyped'}, not an image")
    return failures


def main(argv: list[str] | None = None) -> int:
    paths = [Path(a) for a in (sys.argv[1:] if argv is None else argv)]
    if not paths:
        print("readme-image-check: no README given", file=sys.stderr)
        return 2
    failures = [f for p in paths for f in check(p)]
    if failures:
        print("\n".join(failures))
        return 1
    print(f"readme-image-check: {len(paths)} README(s), every remote image loads.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
