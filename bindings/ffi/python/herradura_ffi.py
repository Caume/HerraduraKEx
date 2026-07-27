"""ctypes wrapper around libherradura_ffi (bindings/ffi/herradura_shim.c).

Opt-in fast path for performance-sensitive users: calls into the C
implementation instead of the pure-Python suite. Packaged separately from
HerraduraCli/primitives.py, which stays on the pedagogical native Python
suite. Build the shared library first:

    bash bindings/ffi/build.sh

Scope: the classical v1.4.0 quartet (HKEX-GF, HSKE, HPKS, HPKE). NL/PQC and
Stern-F protocols are not exposed through this binding — see TODO #137.

Usage:
    from herradura_ffi import Herradura
    h = Herradura()
    priv = h.random_bytes()
    pub = h.hkex_gf_pubkey(priv)
"""

import ctypes
import os
import platform

KEYBYTES = 32
_KeyBuf = ctypes.c_uint8 * KEYBYTES


def _default_lib_path():
    here = os.path.dirname(os.path.abspath(__file__))
    name = "libherradura_ffi.dylib" if platform.system() == "Darwin" else "libherradura_ffi.so"
    return os.path.join(here, "..", name)


class HerraduraFFIError(RuntimeError):
    pass


class Herradura:
    """Loads libherradura_ffi and exposes the classical protocol quartet."""

    def __init__(self, lib_path=None):
        lib_path = lib_path or _default_lib_path()
        try:
            self._lib = ctypes.CDLL(lib_path)
        except OSError as exc:
            raise HerraduraFFIError(
                f"could not load {lib_path!r}; build it with "
                f"`bash bindings/ffi/build.sh` first"
            ) from exc
        self._bind()

    def _bind(self):
        lib = self._lib

        lib.hffi_keybytes.restype = ctypes.c_int
        if lib.hffi_keybytes() != KEYBYTES:
            raise HerraduraFFIError("KEYBYTES mismatch between binding and shared library")

        lib.hffi_hkex_gf_pubkey.argtypes = [_KeyBuf, _KeyBuf]
        lib.hffi_hkex_gf_pubkey.restype = None

        lib.hffi_hkex_gf_agree.argtypes = [_KeyBuf, _KeyBuf, _KeyBuf]
        lib.hffi_hkex_gf_agree.restype = ctypes.c_int

        lib.hffi_hske_encrypt.argtypes = [_KeyBuf, _KeyBuf, _KeyBuf]
        lib.hffi_hske_encrypt.restype = None

        lib.hffi_hske_decrypt.argtypes = [_KeyBuf, _KeyBuf, _KeyBuf]
        lib.hffi_hske_decrypt.restype = None

        lib.hffi_hpks_sign.argtypes = [_KeyBuf, _KeyBuf, _KeyBuf, _KeyBuf]
        lib.hffi_hpks_sign.restype = None

        lib.hffi_hpks_verify.argtypes = [_KeyBuf, _KeyBuf, _KeyBuf, _KeyBuf]
        lib.hffi_hpks_verify.restype = ctypes.c_int

        lib.hffi_hpke_encrypt.argtypes = [_KeyBuf, _KeyBuf, _KeyBuf, _KeyBuf]
        lib.hffi_hpke_encrypt.restype = ctypes.c_int

        lib.hffi_hpke_decrypt.argtypes = [_KeyBuf, _KeyBuf, _KeyBuf, _KeyBuf]
        lib.hffi_hpke_decrypt.restype = ctypes.c_int

    @staticmethod
    def random_bytes():
        return os.urandom(KEYBYTES)

    @staticmethod
    def _buf(data):
        if len(data) != KEYBYTES:
            raise ValueError(f"expected {KEYBYTES} bytes, got {len(data)}")
        return _KeyBuf.from_buffer_copy(data)

    # HKEX-GF

    def hkex_gf_pubkey(self, priv):
        priv_b, out = self._buf(priv), _KeyBuf()
        self._lib.hffi_hkex_gf_pubkey(priv_b, out)
        return bytes(out)

    def hkex_gf_agree(self, my_priv, their_pub):
        priv_b, pub_b, out = self._buf(my_priv), self._buf(their_pub), _KeyBuf()
        ok = self._lib.hffi_hkex_gf_agree(priv_b, pub_b, out)
        return bytes(out) if ok else None

    # HSKE

    def hske_encrypt(self, pt, key):
        pt_b, key_b, out = self._buf(pt), self._buf(key), _KeyBuf()
        self._lib.hffi_hske_encrypt(pt_b, key_b, out)
        return bytes(out)

    def hske_decrypt(self, ct, key):
        ct_b, key_b, out = self._buf(ct), self._buf(key), _KeyBuf()
        self._lib.hffi_hske_decrypt(ct_b, key_b, out)
        return bytes(out)

    # HPKS (Schnorr)

    def hpks_sign(self, msg, priv):
        msg_b, priv_b = self._buf(msg), self._buf(priv)
        R_out, s_out = _KeyBuf(), _KeyBuf()
        self._lib.hffi_hpks_sign(msg_b, priv_b, R_out, s_out)
        return bytes(R_out), bytes(s_out)

    def hpks_verify(self, msg, pub, R, s):
        args = [self._buf(x) for x in (msg, pub, R, s)]
        return bool(self._lib.hffi_hpks_verify(*args))

    # HPKE (El Gamal)

    def hpke_encrypt(self, pt, pub):
        pt_b, pub_b = self._buf(pt), self._buf(pub)
        R_out, ct_out = _KeyBuf(), _KeyBuf()
        ok = self._lib.hffi_hpke_encrypt(pt_b, pub_b, R_out, ct_out)
        return (bytes(R_out), bytes(ct_out)) if ok else (None, None)

    def hpke_decrypt(self, ct, R, priv):
        ct_b, R_b, priv_b = self._buf(ct), self._buf(R), self._buf(priv)
        pt_out = _KeyBuf()
        ok = self._lib.hffi_hpke_decrypt(ct_b, R_b, priv_b, pt_out)
        return bytes(pt_out) if ok else None
