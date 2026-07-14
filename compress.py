#!/usr/bin/env python3
"""Compress a file/folder into a password-protected CSTA (custar) archive."""

from __future__ import annotations

import argparse
import getpass
import sys

from custar import pack


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="CSTA compress: encrypt and pack a file or directory.",
    )
    parser.add_argument("src", help="path to compress (file or directory)")
    parser.add_argument("dst", help="output archive path (e.g. out.cst)")
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
        confirm = getpass.getpass("Confirm: ")
        if password != confirm:
            print("passwords do not match", file=sys.stderr)
            return 1
    if not password:
        print("password must not be empty", file=sys.stderr)
        return 1

    try:
        pack(args.src, args.dst, password, workers=args.jobs)
    except Exception as exc:
        print(f"compress failed: {exc}", file=sys.stderr)
        return 1

    print(f"ok: {args.src} -> {args.dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
