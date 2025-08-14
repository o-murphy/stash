#!/usr/bin/env python

import sys
import os
import json
import argparse
from pathlib import Path

import pytz

from datetime import datetime
from difflib import unified_diff

try:
    import console
except ImportError:
    console = None


# Define ANSI color codes
ANSI_GREEN = "\033[92m"  # For added lines (+)
ANSI_RED = "\033[91m"    # For removed lines (-)
ANSI_RESET = "\033[0m"   # To reset the color


# _____________________________________________________
def argue(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("lhs", type=Path)
    parser.add_argument("rhs", type=Path)
    args = parser.parse_args(args)
    if args.verbose:
        json.dump(vars(args), sys.stderr, indent=4)
    return args


# _____________________________________________________
def sn(x):
    return "%s\n" % x


# _____________________________________________________
def modified(f):
    lmt = os.path.getmtime(f)
    est = pytz.timezone("Australia/Sydney")
    gmt = pytz.timezone("GMT")
    tzf = "%Y-%m-%d %H:%M:%S"
    gdt = datetime.utcfromtimestamp(lmt)
    gdt = gmt.localize(gdt)
    adt = est.normalize(gdt.astimezone(est))
    return adt.strftime(tzf)


# _____________________________________________________
def diff(lhs: Path, rhs: Path):
    if not lhs.is_file():
        sys.stderr.write("%s not a file\n" % lhs)
        sys.exit(1)
    if rhs.is_dir():
        rhs = "%s/%s" % (rhs, os.path.basename(lhs))
    if not rhs.is_file():
        sys.stderr.write("%s not a file\n" % rhs)
        sys.exit(1)

    with open(lhs, "r", encoding="utf-8") as fp:
        flhs = fp.readlines()

    with open(rhs, "r", encoding="utf-8") as fp:
        frhs = fp.readlines()

    diffs = unified_diff(
        flhs,
        frhs,
        fromfile=lhs.as_posix(),
        tofile=rhs.as_posix(),
        fromfiledate=modified(lhs),
        tofiledate=modified(rhs),
    )
    for line in diffs:
        if console:
            # Use the 'console' module if available
            if line.startswith("+"):
                console.set_color(0, 1, 0)
            elif line.startswith("-"):
                console.set_color(0, 0, 1)
            else:
                console.set_color(1, 1, 1)
            sys.stdout.write(line)
        else:
            # Use ANSI escape codes if 'console' is not available
            if line.startswith("+"):
                sys.stdout.write(f"{ANSI_GREEN}")
            elif line.startswith("-"):
                sys.stdout.write(f"{ANSI_RED}")
            else:
                # Print other lines (context, headers) without color
                sys.stdout.write(f"{ANSI_RESET}")
            sys.stdout.write(line)
    return


# _____________________________________________________
def main(args):
    if console:
        console.clear()
    else:
        sys.stdout.write("\033[H\033[2J")
    args = argue(args)
    try:
        diff(args.lhs, args.rhs)
    except FileNotFoundError:
        sys.stderr.write("%s not found\n" % args.lhs)
    except KeyboardInterrupt:
        sys.stderr.write("Interrupted by user\n")
    except Exception as e:
        sys.stderr.write(f"diff: error: {e}\n")
    return


# _____________________________________________________
if __name__ == "__main__":
    main(sys.argv[1:])
