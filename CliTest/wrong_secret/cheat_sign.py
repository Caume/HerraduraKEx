"""CliTest/wrong_secret/cheat_sign.py TRUE_KEY -- CLI-ARGS...  -- TODO #410.

Run the Python CLI's own command (sign / cred-prove) with the suite patched so
that the prover works against TRUE_KEY's PUBLIC statement while the key it is
handed holds a different secret: #409's cheat, a wrong witness for the real
statement, which a verifier must reject.  The honest CLI never produces one --
it derives the statement from the secret it holds (Stern's syndrome, RNL's C)
or refuses outright (HCRED's witness check) -- so without this patch no probe
reaches the verifier with it.  Passed TRUE_KEY itself, it is the control: the
patched prover must still produce what every verifier accepts.
"""
import os, sys, inspect
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'HerraduraCli'))
true_key = sys.argv[1]; assert sys.argv[2] == '--'
sys.argv = ['herradura.py'] + sys.argv[3:]
import herradura as H, codec
S = H._suite_mod
FIRED = []
def counted(f):                            # the patch must be REACHED, or the probe
    def g(*a, **k):                        # silently becomes a plain wrong-key test
        FIRED.append(1); return f(*a, **k)
    return g
label, der = codec.pem_unwrap(open(true_key).read())
if 'STERN' in label:                       # short form: sign against the TRUE syndrome
    e1, seed1, n1 = codec.der_parse_seq(der)[:3]
    orig = S._stern_syndrome                # the short form's signer calls it (herradura.py)
    S._stern_syndrome = counted(lambda seed, e, n, k: orig(seed1, e1, n, k))
elif 'HKEX-RNL' in label:                  # rnl-sigma: prove against the TRUE C
    s1, m1, n1, _ = H._decode_rnl_privkey(codec.der_parse_seq(der))
    C1 = H._rnl_derive_C(m1, s1, n1)
    H._rnl_derive_C = counted(lambda m, s, n: C1)
elif 'HCRED' in label:                     # HCRED: drop the prover's witness check
    src = inspect.getsource(S._hcred_witness)
    R1 = 'raise ValueError("hcred witness does not match syndrome y")'
    R2 = 'raise ValueError("hcred witness does not match public key C")'
    if R1 not in src or R2 not in src:   # a silent no-op patch would test nothing
        sys.exit('cheat_sign.py: _hcred_witness no longer has its two checks; re-point this patch')
    src = src.replace(R1, 'pass').replace(R2, 'v = min(max(v, 0), (1 << eb) - 1)')
    exec(compile(src, 'lenient', 'exec'), S.__dict__)
    S._hcred_witness = counted(S._hcred_witness)
else:
    sys.exit(f'cheat_sign.py: no patch for {label!r}')
# Two Stern paths need no patch: the long form's signer takes no syndrome at
# all, and a ring signer's statement is the ring's public keys, not its own.
NO_PATCH = 'STERN' in label and (n1 > 256 or 'hpks-ring' in sys.argv)
try:
    H.main()
finally:
    if not FIRED and not NO_PATCH:
        sys.stderr.write('cheat_sign.py: the patched function was never called\n')
        os._exit(3)
