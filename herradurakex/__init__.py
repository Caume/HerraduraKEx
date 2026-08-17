# herradurakex/__init__.py — PyPI packaging wrapper (TODO #191)
#
# This package does not re-implement the suite: it loads the canonical
# ``Herradura cryptographic suite.py`` (repo root) and re-exports its public
# names, so `pip install herradurakex` gets the exact same behavior as
# running from a source checkout. The files under herradurakex/_vendor/ are
# symlinks to the real sources (kept in sync automatically, single source of
# truth) and are bundled as package data for distribution — see
# pyproject.toml's [tool.setuptools.package-data].
import importlib.util
import os

__version__ = "2.1.3"

_VENDOR_DIR = os.path.join(os.path.dirname(__file__), '_vendor')
_SUITE_PATH = os.path.join(_VENDOR_DIR, 'Herradura cryptographic suite.py')


def _load_suite():
    spec = importlib.util.spec_from_file_location('herradura_suite', _SUITE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


suite = _load_suite()

# Re-export every public (non-underscore) name from the suite module, e.g.
# BitArray, fscx_revolve, hkex_*, hske_*, hpks_*, hpke_*, gf_mul, gf_pow,
# KEYBITS, GF_POLY, GF_GEN, ORD, and the NL/PQC/Stern/XMSS/HCRED extensions.
# `suite` above remains available for the full surface, including the
# underscore-prefixed internals used by HerraduraCli/primitives.py.
globals().update({k: v for k, v in vars(suite).items() if not k.startswith('_')})
