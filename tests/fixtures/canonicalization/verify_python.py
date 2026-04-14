#!/usr/bin/env python3
"""
Canonicalization fixture runner — Python.

Verifies that the Python sha256 output for each vector matches the
expected value in vectors.json. Exits 0 on success, 1 on failure.

Usage:
    python tests/fixtures/canonicalization/verify_python.py
    python tests/fixtures/canonicalization/verify_python.py --compute
        (prints actual hashes for __COMPUTED__ vectors)
"""
import hashlib
import json
import sys
from pathlib import Path

VECTORS_PATH = Path(__file__).parent / "vectors.json"


def canonical_fingerprint(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def main():
    compute_mode = "--compute" in sys.argv
    vectors = json.loads(VECTORS_PATH.read_text())["vectors"]
    failures = []

    for v in vectors:
        name = v["name"]
        actual = canonical_fingerprint(v["input"])
        expected = v["expected_sha256"]

        if expected.startswith("__COMPUTED__"):
            if compute_mode:
                print(f"  {name}: {actual}")
            continue

        if expected.startswith("__MUST_NOT_EQUAL__"):
            must_not = expected.replace("__MUST_NOT_EQUAL__", "")
            if actual == must_not:
                failures.append(f"FAIL {name}: hash should differ from {must_not} but matched")
            else:
                print(f"  OK  {name}: correctly differs from reference hash")
            continue

        if actual == expected:
            print(f"  OK  {name}")
        else:
            failures.append(f"FAIL {name}:\n     expected: {expected}\n     actual:   {actual}")

    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f"  {f}")
        sys.exit(1)

    print("\nAll vectors passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
