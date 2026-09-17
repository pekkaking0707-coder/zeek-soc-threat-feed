"""Zeek TSV log reader — streaming parser for dns.log/conn.log etc. (PLAN §4).

Zeek TSV format: comment lines start with '#'; the '#fields' line fixes column
order. iter_rows yields plain dicts keyed by field name. follow() polls for
appended lines so live capture satisfies constraint (c) — incremental
processing, no batch pass.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path


def _read_fields(path: Path) -> list[str]:
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#fields"):
                return line.rstrip("\n").split("\t")[1:]
            if not line.startswith("#"):
                break
    raise ValueError(f"no #fields header found in {path}")


def iter_rows(path: str | Path) -> Iterator[dict]:
    """Yield each data row as {field: value} using the file's #fields header."""
    path = Path(path)
    fields: list[str] | None = None
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line:
                continue
            if fields is None:
                continue
            values = line.split("\t")
            yield dict(zip(fields, values))


def _parse_row(line: str, fields: list[str]) -> dict:
    return dict(zip(fields, line.split("\t")))


def follow(path: str | Path, poll_s: float = 1.0) -> Iterator[dict]:
    """tail -F semantics: stream new rows forever (live Zeek capture)."""
    path = Path(path)
    while not path.exists():
        time.sleep(poll_s)
        continue
    fields: list[str] | None = None
    with path.open(encoding="utf-8", errors="replace") as fh:
        fh.seek(0, 2)  # skip historical content; live only
        while True:
            line = fh.readline()
            if not line:
                time.sleep(poll_s)
                continue
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line or fields is None:
                continue
            yield _parse_row(line, fields)
