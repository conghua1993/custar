#!/usr/bin/env python3
"""Decompress a password-protected CSTA (custar) archive."""

from __future__ import annotations

import argparse
import getpass
import sys

from custar import unpack


def _print_progress(done: int, total: int, path: str) -> None:
    if total <= 0:
        print("decompress: no files to extract", flush=True)
        return
    pct = (100 * done) // total
    print(f"[{done}/{total}] {pct:3d}%  {path}", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="CSTA decompress: decrypt and unpack an archive.",
    )
    parser.add_argument("src", help="input archive path")
    parser.add_argument("dst", help="output directory")
    parser.add_argument(
        "-p",
        "--password",
        help="archive password (prompted if omitted)",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=0,
        help="worker threads (default: auto)",
    )
    args = parser.parse_args(argv)

    password = args.password
    if not password:
        password = getpass.getpass("Password: ")
    if not password:
        print("password must not be empty", file=sys.stderr)
        return 1

    try:
        unpack(
            args.src,
            args.dst,
            password,
            workers=args.jobs,
            progress=_print_progress,
        )
    except Exception as exc:
        print(f"decompress failed: {exc}", file=sys.stderr)
        return 1

    print(f"ok: {args.src} -> {args.dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
