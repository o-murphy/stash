#!/usr/bin/env python
"""Print the contents of the given files."""

import argparse
import fileinput
import string
import sys
from collections.abc import Sequence


def filter_non_printable(s: str) -> str:
    return "".join(
        [c if c.isalnum() or c.isspace() or c in string.punctuation else " " for c in s]
    )


def main(args: Sequence[str]) -> None:
    p = argparse.ArgumentParser(description=__doc__)
    # NOTE: keep as plain str, not Path - fileinput's "-" stdin sentinel is a
    # direct string comparison (`self._filename == '-'`), which a Path never
    # equals, breaking `some_cmd | cat -`.
    p.add_argument("files", action="store", nargs="*", help="files to print")
    ns = p.parse_args(args)

    try:
        with fileinput.input(files=ns.files, encoding="utf-8") as fin:
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
