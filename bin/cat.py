#!/usr/bin/env python
"""Print the contents of the given files."""

import argparse
import fileinput
import string
import sys
from collections.abc import Sequence
from pathlib import Path


def filter_non_printable(s: str) -> str:
    return "".join(
        [c if c.isalnum() or c.isspace() or c in string.punctuation else " " for c in s]
    )


def main(args: Sequence[str]) -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("files", action="store", type=Path, nargs="*", help="files to print")
    ns = p.parse_args(args)

    try:
        with fileinput.input(
            files=ns.files, openhook=fileinput.hook_encoded("utf-8")
        ) as fin:
            for line in fin:
                print(filter_non_printable(line), end="")
    except KeyboardInterrupt:
        print("\nOperation interrupted by user.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print("cat: error: %s" % str(e), file=sys.stderr)
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main(sys.argv[1:])
