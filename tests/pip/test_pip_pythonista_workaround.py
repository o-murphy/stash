"""tests for the Pythonista install-location workaround in bin/pip.py.

See docs/pip_pythonista_workaround.md for the background. These are pure
logic tests: no network access, no StaSh runtime, and no writes under the
real ~/Documents -- unlike tests/pip/test_pip.py, they don't go through
StashTestCase.run_command().
"""

import importlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("stash_bin_pip", ROOT / "bin" / "pip.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _locate_importable_package(name):
    """return the on-disk directory of an importable top-level package, or
    None if it isn't importable in the current interpreter."""
    try:
        module = importlib.import_module(name)
    except ImportError:
        return None
    module_file = getattr(module, "__file__", None)
    if module_file is None:
        return None
    return Path(module_file).resolve().parent


class PipPythonistaWorkaroundTests(unittest.TestCase):
    """tests for the --target-based install workaround and its cleanup."""

    def test_builds_install_args_with_target_not_prefix(self):
        """--target (not --prefix) must be used so no sysconfig-scheme
        directory layout has to be guessed at."""
        args = MODULE._build_get_pip_install_args("/tmp/custom-site-packages")

        self.assertEqual(
            args[:5],
            [
                "install",
                "--target",
                "/tmp/custom-site-packages",
                "--upgrade",
                "--force-reinstall",
            ],
        )
        self.assertEqual(args[-3:], ["pip", "setuptools", "wheel"])

    def test_ensure_user_site_packages_in_path(self):
        MODULE._ensure_user_site_packages_in_path()
        self.assertIn(str(MODULE._SITE_PACKAGES), MODULE.sys.path)

    def test_self_shadow_guard_prevents_recursive_import(self):
        """End-to-end regression test for the original bug: bin/pip.py's
        own directory is always on sys.path (it's the running script's
        directory), and there's no real "pip" package next to it -- just
        this file. Before the find_spec-based guard, a bare `import pip`
        here resolved to the script itself, recursed into the same import
        statement, and crashed with "No module named 'pip._internal';
        'pip' is not a package" instead of cleanly reporting pip as
        missing. Reproduce that exact condition: run this file directly,
        via a fresh interpreter that genuinely has no "pip" package
        importable, from a directory containing only this file."""
        requests_dir = _locate_importable_package("requests")
        if requests_dir is None:
            self.skipTest("could not locate an importable 'requests' package")
        dep_dirs = [requests_dir]
        for dep in ("charset_normalizer", "idna", "urllib3", "certifi"):
            dep_dir = _locate_importable_package(dep)
            if dep_dir is not None:
                dep_dirs.append(dep_dir)

        with tempfile.TemporaryDirectory() as tmp_dir:
            venv_dir = Path(tmp_dir) / "venv"
            subprocess.run(
                [sys.executable, "-m", "venv", "--without-pip", str(venv_dir)],
                check=True,
                capture_output=True,
            )
            venv_python = venv_dir / "bin" / "python3"
            site_packages = next(venv_dir.glob("lib/python*/site-packages"))
            for dep_dir in dep_dirs:
                shutil.copytree(dep_dir, site_packages / dep_dir.name)
            # sanity check: this venv must not have a real "pip" package.
            probe = subprocess.run(
                [str(venv_python), "-c", "import pip"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(probe.returncode, 0, "test venv unexpectedly has pip")

            fake_home = Path(tmp_dir) / "home"
            documents_dir = fake_home / "Documents"
            documents_dir.mkdir(parents=True)
            shutil.copy(ROOT / "bin" / "pip.py", documents_dir / "pip.py")

            result = subprocess.run(
                [str(venv_python), str(documents_dir / "pip.py")],
                input="n\n",
                capture_output=True,
                text=True,
                env={**os.environ, "HOME": str(fake_home)},
                timeout=60,
            )

        self.assertNotIn(
            "not a package",
            result.stdout + result.stderr,
            "self-import shadow regression: " + result.stdout + result.stderr,
        )
        self.assertIn("Pip doesn't seem to be installed", result.stdout)
        self.assertIn("Aborting installation", result.stdout)
        self.assertEqual(result.returncode, 0)

    def test_patches_get_pip_script_to_insert_target(self):
        original = (
            "def determine_pip_install_arguments():\n"
            "    pre_parser = argparse.ArgumentParser()\n"
            "\n"
            "    args.append('pip')\n"
            "\n"
            "    return ['install', '--upgrade', '--force-reinstall'] + args\n"
            "\n"
            "def monkeypatch_for_cert(tmpdir):\n"
            "    pass\n"
        )
        patched = MODULE._patch_get_pip_script(original, "/tmp/custom-site-packages")

        self.assertIn("def _orig_determine_pip_install_arguments():", patched)
        self.assertIn(
            "def determine_pip_install_arguments():\n    args = _orig_determine_pip_install_arguments()",
            patched,
        )
        self.assertIn("--target", patched)
        self.assertIn("/tmp/custom-site-packages", patched)

    def test_patch_does_not_stop_inside_data_block(self):
        """the regex patch must stop at the real function, not a
        `determine_pip_install_arguments` string that happens to appear
        again inside get-pip.py's embedded base85 DATA blob."""
        original = (
            "def determine_pip_install_arguments():\n"
            "    return ['install', '--upgrade', '--force-reinstall']\n"
            "\n"
            'DATA = b"""\n'
            "def determine_pip_install_arguments():\n"
            "    embedded = True\n"
            '"""\n'
        )
        patched = MODULE._patch_get_pip_script(original, "/tmp/custom-site-packages")

        self.assertIn("def _orig_determine_pip_install_arguments():", patched)
        self.assertLess(
            patched.find(
                "def determine_pip_install_arguments():\n    args = _orig_determine_pip_install_arguments()"
            ),
            patched.find('DATA = b"""'),
        )

    def test_patched_script_executes_and_injects_target(self):
        original = "def determine_pip_install_arguments():\n    return ['install', '--upgrade', '--force-reinstall', 'pip']\n"
        patched = MODULE._patch_get_pip_script(original, "/tmp/custom-site-packages")
        namespace = {"__name__": "__main__"}

        exec(patched, namespace)

        self.assertEqual(
            namespace["determine_pip_install_arguments"](),
            [
                "install",
                "--target",
                "/tmp/custom-site-packages",
                "--upgrade",
                "--force-reinstall",
                "pip",
            ],
        )

    def test_remove_pip_console_scripts_clears_known_stub_names(self):
        """installing "pip" via --target drops pip/pip3/pip3.X launcher
        stubs into site-packages/bin/ that lack this file's sys.path setup
        and --target injection; they must be removed after every install
        that touches "pip" so StaSh can't resolve `pip` to one of them."""
        original_target_bin = MODULE._TARGET_BIN
        with tempfile.TemporaryDirectory() as tmp_dir:
            bin_dir = Path(tmp_dir) / "bin"
            bin_dir.mkdir()
            MODULE._TARGET_BIN = bin_dir

            stub_names = (
                "pip",
                f"pip{MODULE.sys.version_info.major}",
                f"pip{MODULE.sys.version_info.major}.{MODULE.sys.version_info.minor}",
            )
            try:
                for name in stub_names:
                    (bin_dir / name).write_text("stub", encoding="utf-8")

                MODULE._remove_pip_console_scripts()

                for name in stub_names:
                    self.assertFalse((bin_dir / name).exists())
            finally:
                MODULE._TARGET_BIN = original_target_bin

    def test_remove_pip_console_scripts_is_a_noop_without_bin_dir(self):
        original_target_bin = MODULE._TARGET_BIN
        MODULE._TARGET_BIN = Path(tempfile.mkdtemp()) / "does-not-exist"
        try:
            MODULE._remove_pip_console_scripts()  # must not raise
        finally:
            MODULE._TARGET_BIN = original_target_bin


if __name__ == "__main__":
    unittest.main()
