#!/usr/bin/env python
"""Interface to pythons built-in garbage collector

Warning: this command may crash StaSh!
Only use it if you know what you are doing!"""

import argparse
import gc
import sys

_stash = globals()["_stash"]


def main():
    parser = argparse.ArgumentParser(
        description="access to pythons built-in garbage collector"
    )
    parser.add_argument(
        "command",
        help="what to do",
        choices=[
            "enable",
            "disable",
            "status",
            "collect",
            "threshold",
            "debug",
            "break",
        ],
        action="store",
    )
    parser.add_argument("args", help="argument for command", action="store", nargs="*")
    ns = parser.parse_args()
    if ns.command == "enable":
        gc.enable()
    elif ns.command == "disable":
        gc.disable()
    elif ns.command == "collect":
        gc.collect()
    elif ns.command == "status":
        if gc.isenabled():
            gcs = _stash.text_color("Enabled", "green")
        else:
            gcs = _stash.text_color("Disabled", "red")
        sys.stdout.write(f"GC status:               {gcs}\n")
        tracked = gc.get_objects()
        n = len(tracked)
        sys.stdout.write(f"Tracked objects:         {n}\n")
        size = sum([sys.getsizeof(e) for e in tracked])
        del tracked  # this list may be big, better delete it
        size = _stash.libcore.sizeof_fmt(size)
        sys.stdout.write(f"Size of tracked objects: {size} \n")
        sys.stdout.write(f"Garbage:                 {len(gc.garbage)}\n")
        gsize = sum([sys.getsizeof(e) for e in gc.garbage])
        gsize = _stash.libcore.sizeof_fmt(gsize)
        sys.stdout.write(f"Size of garbage:         {gsize} \n")
        sys.stdout.write(f"Debug:                   {gc.get_debug()}\n")
    elif ns.command == "threshold":
        if len(ns.args) == 0:
            sys.stdout.write(
                "Threshold:\n   G1: {}\n   G2: {}\n   G3: {}\n".format(
                    *gc.get_threshold()
                )
            )
        elif len(ns.args) > 3:
            errmsg = _stash.text_color(
                "Error: to many arguments for threshold!\n", "red"
            )
            sys.stdout.write(errmsg)
            sys.exit(1)
        else:
            try:
                ts = tuple([int(e) for e in ns.args])
            except ValueError:
                errmsg = _stash.text_color(
                    "Error: expected arguments to be integer!\n", "red"
                )
                sys.stdout.write(errmsg)
                sys.exit(1)
            gc.set_threshold(*ts)
    elif ns.command == "debug":
        if len(ns.args) == 0:
            sys.stdout.write(f"Debug: {gc.get_debug()}\n")
        elif len(ns.args) == 1:
            try:
                flag = int(ns.args[0])
            except ValueError:
                sys.stdout.write(
                    _stash.text_color(
                        "Error: expected argument to be an integer!\n", "red"
                    )
                )
                sys.exit(1)
            gc.set_debug(flag)
        else:
            sys.stdout.write(
                _stash.text_color(
                    "Error: expected exactly one argument for debug!\n", "red"
                )
            )
            sys.exit(1)
    elif ns.command == "break":
        if len(gc.garbage) == 0:
            sys.stdout.write(_stash.text_color("Error: No Garbage found!\n", "red"))
            sys.exit(1)
        else:
            for k in dir(gc.garbage[0]):
                try:
                    delattr(gc.garbage[0], k)
                except:
                    pass
            del gc.garbage[:]


if __name__ == "__main__":
    main()
