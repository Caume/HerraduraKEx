"""
probe_sk_formula.py — Initial algebraic verification that the HKEX
shared secret sk = S_{r+1}·(C⊕C2) is directly computable from the
two public wire values, and that the fundamental identity holds.

Used to confirm the classical break theorem before the full proof.
"""
import ctypes, struct

def mask(n): return (1 << n) - 1
def rol(x,b,n): b%=n; return ((x<<b)|(x>>(n-b)))&mask(n)
def ror(x,b,n): return rol(x,n-b,n)
def M(x,n): return x^rol(x,1,n)^ror(x,1,n)

def Mpow(x,k,n):
    for _ in range(k%(n//2)): x=M(x,n)
    return x

def Spow(x,k,n):
    acc,cur=0,x
    for _ in range(k): acc^=cur; cur=M(cur,n)
    return acc

def fscx(a,b,n): t=a^b; return t^rol(t,1,n)^ror(t,1,n)

def revolve(a,b,k,n):
    for _ in range(k): a=fscx(a,b,n)
    return a

def revolve_n(a,b,nonce,k,n):
    for _ in range(k): a=fscx(a,b,n)^nonce
    return a

n=32; i=8; r=24
A=0xDEADBEEF; B=0xCAFEBABE; A2=0x12345678; B2=0xABCDEF01

C =revolve(A, B, i,n)
C2=revolve(A2,B2,i,n)
N =C^C2

skA=revolve_n(C2,B, N,r,n)^A
skB=revolve_n(C, B2,N,r,n)^A2

sk_direct=Spow(C^C2, r+1, n)

print(f"C            = {C:#010x}")
print(f"C2           = {C2:#010x}")
print(f"N = C^C2     = {N:#010x}")
print(f"skA          = {skA:#010x}")
print(f"skB          = {skB:#010x}")
print(f"S_{{r+1}}·N   = {sk_direct:#010x}")
print()
print(f"skA == skB                  : {skA==skB}")
print(f"skA == S_{{r+1}}·(C^C2)      : {skA==sk_direct}  <- directly computable from public values")

# Verify M^r + S_r = S_{r+1}
test_v=0xDEADC0DE
lhs=Mpow(test_v,r,n)^Spow(test_v,r,n)
rhs=Spow(test_v,r+1,n)
print(f"\nM^r·v ^ S_r·v == S_{{r+1}}·v : {lhs==rhs}")

# Verify fundamental identity: (S_r·M + M^{r+1}·S_i)·v = 0
fund=Spow(M(test_v,n),r,n)^Mpow(Spow(test_v,i,n),r+1,n)
print(f"(S_r·M + M^{{r+1}}·S_i)·v = 0: {fund==0}  (got {fund:#010x})")
