# -*- coding: utf-8 -*-
"""
Install pip package manager
Wraps real pip for StaSh
"""

import importlib.util
import os
import re
import sys
import tempfile
import requests
from pathlib import Path
import ssl

_HOME = Path("~").expanduser()
_DOCUMENTS = _HOME / "Documents"
_SITE_PACKAGES = _DOCUMENTS / "site-packages"
_PIP_BOOTSTRAP_URL = "https://bootstrap.pypa.io/get-pip.py"


def _ensure_user_site_packages_in_path() -> None:
    path = str(_SITE_PACKAGES)
    if path not in sys.path:
        sys.path.insert(0, path)


# Must run before the `pip` detection below: this file is meant to live
# permanently as e.g. ~/Documents/pip.py, and on every run after the first
# successful bootstrap, the real installed "pip" package lives one level
# down in _SITE_PACKAGES, not next to this file. Without this, sys.path[0]
# (this file's own directory) never contains anything but this very file
# named "pip.py", so pip would never be detected as installed.
_ensure_user_site_packages_in_path()

# This file is named pip.py and (by design, to wrap real pip for StaSh) ends
# up on sys.path -- e.g. as sys.path[0], the running script's own directory.
# A plain `import pip` in that situation resolves to this very file instead
# of failing, which then recurses into this same import statement. Locate
# the spec first and make sure it isn't this file before importing for real.
_HAS_PIP = False
try:
    _pip_spec = importlib.util.find_spec("pip")
except (ImportError, ValueError):
    _pip_spec = None

if _pip_spec is not None and _pip_spec.origin not in (
    None,
    __file__,
    os.path.abspath(__file__),
):
    try:
        from pip._internal.cli.main import main

        _HAS_PIP = True
    except ImportError:
        _HAS_PIP = False

ssl._create_default_https_context = ssl._create_unverified_context

v_maj, v_min, v_patch, *_ = sys.version_info
assert v_maj >= 3, "Python 3.10 or a more recent version is required."
assert v_min >= 10, "Python 3.10 or a more recent version is required."


def _build_get_pip_install_args(target_dir: str):
    # --target (rather than --prefix) installs package files flatly and
    # directly into target_dir, with no scheme-dependent "lib/pythonX.Y/
    # site-packages" nesting to guess at. Pythonista ships a non-standard
    # sysconfig install scheme where that nesting doesn't land where a
    # normal CPython build would put it (its default scheme even resolves
    # into the read-only app bundle), so --target sidesteps the whole
    # class of "where did pip actually write the files" guessing.
    return [
        "install",
        "--target",
        target_dir,
        "--upgrade",
        "--force-reinstall",
        "pip",
        "setuptools",
        "wheel",
    ]


_TARGET_BIN = _SITE_PACKAGES / "bin"


def _remove_pip_console_scripts() -> None:
    # Installing the "pip" package via --target also drops its own
    # pip/pip3/pip3.X launcher stubs into site-packages/bin. They don't
    # have this file's self-shadow guard, sys.path setup, or --target
    # injection, so if StaSh's command resolution ever found one of these
    # ahead of this file, it'd break exactly like the old Documents/bin/pip
    # mixup did. We don't need them -- this file is what StaSh should use.
    if not _TARGET_BIN.exists():
        return
    for name in (
        "pip",
        f"pip{sys.version_info.major}",
        f"pip{sys.version_info.major}.{sys.version_info.minor}",
    ):
        stub = _TARGET_BIN / name
        try:
            stub.unlink()
        except OSError:
            pass


def _patch_get_pip_script(code: str, target_dir: str) -> str:
    code = code.replace(
        '    cert_path = os.path.join(tmpdir, "cacert.pem")\n',
        '    cert_dir = os.path.join(os.path.expanduser("~"), "Documents", ".pip")\n'
        "    os.makedirs(cert_dir, exist_ok=True)\n"
        '    cert_path = os.path.join(cert_dir, "cacert.pem")\n',
    )

    pattern = re.compile(
        r"(?ms)^def determine_pip_install_arguments\(\):\n(?P<body>.*?)(?=^def (?:monkeypatch_for_cert|bootstrap|main)|^DATA =|\Z)"
    )

    def _replace(match: re.Match[str]) -> str:
        body = match.group("body")
        return (
            "def _orig_determine_pip_install_arguments():\n"
            f"{body}"
            "def determine_pip_install_arguments():\n"
            "    args = _orig_determine_pip_install_arguments()\n"
            '    if "--prefix" not in args and "--target" not in args:\n'
            f'        args = ["install", "--target", {target_dir!r}] + args[1:]\n'
            "    return args\n"
        )

    return pattern.sub(_replace, code, count=1)


def _purge_cached_pip_modules() -> None:
    # StaSh runs commands inside one long-lived interpreter rather than a
    # fresh subprocess per command, so a broken/self-shadowed "pip" entry
    # from an earlier attempt in the same session can still be sitting in
    # sys.modules. get-pip's own bootstrap does a plain `import pip` and
    # would silently reuse that stale entry instead of the real package it
    # is about to unpack, so clear it out right before running get-pip.
    for _mod_name in list(sys.modules):
        if _mod_name == "pip" or _mod_name.startswith("pip."):
            del sys.modules[_mod_name]


def _download_and_install_pip():
    _purge_cached_pip_modules()

    code = requests.get(_PIP_BOOTSTRAP_URL).content.decode(errors="ignore")

    target_arg = str(_SITE_PACKAGES)
    code = _patch_get_pip_script(code, target_arg)

    tmp_file = None
    try:
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".py") as handle:
            tmp_file = handle.name
            handle.write(code)
        namespace = {"__name__": "__main__", "__file__": tmp_file}
        try:
            exec(compile(code, tmp_file, "exec"), namespace)
        except SystemExit as e:
            if e.code != 0:
                raise RuntimeError(f"get-pip failed with exit code {e.code}")
        except KeyboardInterrupt:
            pass
    finally:
        if tmp_file and os.path.exists(tmp_file):
            os.remove(tmp_file)

    # --target already wrote package files directly into _SITE_PACKAGES --
    # no scheme-dependent nested directory to discover and copy out of.
    _remove_pip_console_scripts()


if __name__ == "__main__":
    # This file is meant to live permanently as e.g. ~/Documents/pip.py --
    # StaSh resolves the "pip" command to it every time, both before pip
    # exists (the bootstrap branch below) and after (the _HAS_PIP branch),
    # so there's no separate wrapper file to keep in sync with this logic.
    _SITE_PACKAGES.mkdir(parents=True, exist_ok=True)

    if _HAS_PIP:
        sys.argv[0] = re.sub(r"(-script\.pyw?|\.exe)?$", "", sys.argv[0])
        if "install" in sys.argv:
            if "--prefix" not in sys.argv and "--target" not in sys.argv:
                sys.argv.extend(["--target", str(_SITE_PACKAGES)])
            ret = main()
            # Covers "pip install pip -U" / "pip install --upgrade pip",
            # which would otherwise silently recreate the stub scripts.
            _remove_pip_console_scripts()
            sys.exit(ret)
        else:
            sys.exit(main())

    else:
        print("Pip doesn't seem to be installed")
        try_install = input("Do you want to install Pip? [Y/n]")
        if try_install.lower() in {"y", "yes"}:
            print("Installing Pip")
            try:
                _download_and_install_pip()
                print("Pip installation done!")
            except Exception as e:
                print(e)
        else:
            print("Aborting installation")
