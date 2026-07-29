# pip on Pythonista: install-location workaround
-----------------------

`bin/pip.py` bootstraps and then wraps the real, official `pip` for StaSh. It
exists because Pythonista's bundled Python ships a non-standard, partially
broken install setup that plain `pip`/`get-pip.py` can't work around on
their own.

## Motivation

Pythonista's Python has two problems that combine to make a naive
`pip install` fail:

1. **The default install scheme is not writable.** Running `pip install
   <anything>` with no explicit destination fails with:
   ```
   Defaulting to user installation because normal site-packages is not writeable
   ...
   ERROR: Could not install packages due to an OSError: [Errno 1] Operation not permitted:
   '/var/containers/.../Pythonista3.app/Frameworks/Py3Kit.framework/pylib/lib'
   ```
   Even pip's own "fall back to `--user`" logic resolves into the
   **read-only app bundle**. This was confirmed on-device, not just assumed.
2. **There is no persistent, one-time fix.** `pip.conf`/`PIP_CONFIG_FILE`
   and `sitecustomize.py`-based approaches (setting a default install
   location once, globally) were both tried on-device and don't work
   reliably here.

So an explicit, writable destination has to be passed to pip on **every**
invocation, forever — `bin/pip.py` is what does that.

## How it works

- On first run, if no real pip is importable yet, `bin/pip.py` downloads
  `get-pip.py` fresh from `https://bootstrap.pypa.io/get-pip.py` and patches
  it to inject `--target ~/Documents/site-packages` into its install
  arguments, and to write its bundled CA cert under `~/Documents/.pip/`
  (writable) instead of a scratch tmpdir.
- `--target` (not `--prefix`) is used deliberately: `--prefix`'s
  site-packages sub-path depends on the platform's `sysconfig` install
  scheme, and Pythonista's scheme doesn't lay things out where a normal
  CPython build would (two different guesses at that nested path were each
  wrong on-device, and the cleanup step that followed silently deleted the
  freshly-finished install before anyone could look). `--target` always
  installs files flatly and directly into the given directory, so there's
  no scheme to guess at.
- `bin/pip.py` is meant to live **permanently** as `~/Documents/pip.py` and
  StaSh should resolve the `pip` command to it ahead of this repository's
  own bundled copy at `bin/pip.py` — on every run, not just the first. Once
  real pip is importable from `~/Documents/site-packages`, it injects the
  same `--target` for any `install` subcommand and otherwise calls straight
  through to pip's own `main()` (`show`/`list`/`uninstall`/... need no
  destination override, since they resolve packages via `sys.path`).
- Installing/upgrading `pip` itself via `--target` also drops
  `pip`/`pip3`/`pip3.X` launcher-stub scripts into `site-packages/bin/`.
  Those stubs have none of this file's `sys.path` setup, self-shadow guard,
  or `--target` injection, so if StaSh's command resolution ever found one
  of them ahead of `bin/pip.py`, `pip` would break again. `bin/pip.py`
  deletes them after every install that touches `pip`.

## Known pitfalls fixed here (read before changing this file)

- **Self-import shadow.** `pip.py`'s own directory is always on `sys.path`
  (it's the running script's directory), and there's no real `pip` package
  next to it — just this file. A plain `import pip` therefore resolves to
  *this file*, recurses into the same import, and fails once Python
  realizes the self-imported module isn't a package
  (`No module named 'pip._internal'; 'pip' is not a package`). The failed
  import also leaves a broken `pip` entry cached in `sys.modules`, which
  then poisons `get-pip.py`'s own internal `import pip` later — even though
  `get-pip.py` puts the real pip at the front of `sys.path` first. Fixed by
  resolving pip's module spec via `importlib.util.find_spec` and refusing
  to import it if the spec's origin is this same file, plus purging any
  stray `pip`/`pip.*` entries from `sys.modules` right before running
  `get-pip.py` (StaSh runs commands in one long-lived interpreter, not a
  fresh process per command, so stale pollution from an earlier failed
  attempt in the same session can otherwise persist).
- **Path-setup/detection ordering.** `sys.path` must include
  `~/Documents/site-packages` *before* checking whether real pip is
  importable. Otherwise, on every run after the first, the script would
  look for `pip` only next to itself (where there's nothing but this file)
  and always report "Pip doesn't seem to be installed" even though it's
  already installed one directory down.

## Testing

Every fix here was verified against a **local simulation**, not a real
Pythonista device — see `tests/pip/test_pip_pythonista_workaround.py` for
the pure-logic unit tests (no network, no StaSh runtime required). They
cover: the self-shadow guard, the `get-pip.py`-patching regex, and the
stub-script cleanup. Where device-specific behavior mattered (confirming
pip's default scheme actually resolves into the read-only app bundle, or
that `--target` installs still work fine with `show`/`list`/`uninstall`
once `sys.path` is correct), those were checked against real on-device
error output.
