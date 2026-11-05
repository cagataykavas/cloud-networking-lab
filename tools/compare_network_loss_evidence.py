#!/usr/bin/env python3
"""Compare two retained partial-loss benchmarks under one exact runtime."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

from tools.network_loss_evidence import (
    PartialLossBenchmarkEvidence,
    compare_partial_loss_benchmarks,
)


MAX_EVIDENCE_BYTES = 64 * 1024


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("benchmark JSON contains duplicate keys")
        document[key] = value
    return document


def load_evidence(path: Path) -> PartialLossBenchmarkEvidence:
    """Read one bounded regular file without following a final symlink."""
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 1 <= metadata.st_size <= MAX_EVIDENCE_BYTES
        ):
            raise ValueError("benchmark evidence must be a bounded regular file")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 16 * 1024):
            size += len(chunk)
            if size > MAX_EVIDENCE_BYTES:
                raise ValueError("benchmark evidence grew beyond the size limit")
            chunks.append(chunk)
        payload = b"".join(chunks)
        if len(payload) != metadata.st_size:
            raise ValueError("benchmark evidence changed while being read")
    except OSError as exc:
        raise ValueError(
            "cannot read benchmark evidence without following links"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        document = json.loads(payload, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("benchmark evidence is not valid JSON") from exc
    return PartialLossBenchmarkEvidence.from_dict(document)


def write_receipt(document: dict[str, Any], output: Path) -> None:
    """Atomically persist a private deterministic comparison receipt."""
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output.parent,
        prefix=f".{output.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, allow_nan=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(temporary, 0o600)
        temporary.replace(output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Gate a partial-loss benchmark against a compatible retained baseline."
        )
    )
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument(
        "--max-failure-rate-increase-basis-points",
        type=int,
        default=250,
    )
    parser.add_argument(
        "--max-elapsed-increase-basis-points",
        type=int,
        default=2_000,
    )
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        inputs = {args.baseline.resolve(), args.candidate.resolve()}
        if len(inputs) != 2:
            raise ValueError("baseline and candidate must be distinct files")
        if args.output is not None and args.output.resolve() in inputs:
            raise ValueError("output must not replace benchmark evidence")
        comparison = compare_partial_loss_benchmarks(
            load_evidence(args.baseline),
            load_evidence(args.candidate),
            max_failure_rate_increase_basis_points=(
                args.max_failure_rate_increase_basis_points
            ),
            max_elapsed_increase_basis_points=(args.max_elapsed_increase_basis_points),
        )
        document = comparison.as_dict()
        if args.output is None:
            print(json.dumps(document, allow_nan=False, indent=2, sort_keys=True))
        else:
            write_receipt(document, args.output)
        return 0 if comparison.accepted else 3
    except (OSError, TypeError, ValueError) as exc:
        print(f"benchmark comparison rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
