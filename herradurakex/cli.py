# herradurakex/cli.py — console-script entry point (TODO #191)
#
# Delegates to the canonical OpenSSL-style CLI in HerraduraCli/herradura.py
# (bundled via herradurakex/_vendor/), so `pip install herradurakex` also
# provides the `herradurakex` command with the same genpkey/pkey/kex/enc/
# dec/sign/verify/dgst/encfile/decfile subcommands documented in
# HerraduraCli's README and docs/TUTORIAL.md.
import importlib.util
import os
import sys

_VENDOR_CLI_DIR = os.path.join(os.path.dirname(__file__), '_vendor', 'HerraduraCli')


def main():
    # herradura.py does `import primitives` / `import codec` (siblings in
    # HerraduraCli/), so that directory must be on sys.path before it loads.
    if _VENDOR_CLI_DIR not in sys.path:
        sys.path.insert(0, _VENDOR_CLI_DIR)
    spec = importlib.util.spec_from_file_location(
        'herradura_cli_impl', os.path.join(_VENDOR_CLI_DIR, 'herradura.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main()


if __name__ == '__main__':
    main()
