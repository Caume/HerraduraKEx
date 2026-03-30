###
#    Herradura KEx (HKEX)- a Key exchange scheme in the style of Diffie-Hellman Key Exchange,
#    based on the FSCX function.
#
#    Copyright (C) 2017-2026 Omar Alejandro Herrera Reyna
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the MIT License or the GNU General Public License
#    as published by the Free Software Foundation, either version 3 of the License,
#    or (at your option) any later version.
#
#    Under the terms of the GNU General Public License, please also consider that:
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###

"""Minimal example of the Herradura Key Exchange algorithm."""

from secrets import randbits
import argparse


class BitArray:
    """Fixed-width bit string backed by a Python int.
    Supports XOR, in-place rotation, equality, and hex/bytes/uint I/O.
    Size must be a positive multiple of 8.
    """

    __slots__ = ('_val', '_size', '_mask')

    def __init__(self, size: int, value: int = 0):
        self._size = size
        self._mask = (1 << size) - 1
        self._val = int(value) & self._mask

    @property
    def uint(self) -> int:
        return self._val

    @uint.setter
    def uint(self, value: int):
        self._val = int(value) & self._mask

    @property
    def bytes(self) -> bytes:
        return self._val.to_bytes(self._size // 8, 'big')

    @bytes.setter
    def bytes(self, data: bytes):
        self._val = int.from_bytes(data, 'big') & self._mask

    @property
    def hex(self) -> str:
        return f'{self._val:0{self._size // 4}x}'

    def copy(self) -> 'BitArray':
        return BitArray(self._size, self._val)

    def rol(self, n: int) -> None:
        """Rotate left in-place by n bits."""
        n %= self._size
        if n:
            self._val = ((self._val << n) | (self._val >> (self._size - n))) & self._mask

    def ror(self, n: int) -> None:
        """Rotate right in-place by n bits."""
        n %= self._size
        if n:
            self._val = ((self._val >> n) | (self._val << (self._size - n))) & self._mask

    def __xor__(self, other: 'BitArray') -> 'BitArray':
        return BitArray(self._size, self._val ^ other._val)

    def __ixor__(self, other: 'BitArray') -> 'BitArray':
        self._val ^= other._val
        return self

    def __eq__(self, other: object) -> bool:
        if isinstance(other, BitArray):
            return self._size == other._size and self._val == other._val
        return NotImplemented

    def __str__(self) -> str:
        return f'0x{self.hex}'

    def __repr__(self) -> str:
        return f'BitArray({self._size}, 0x{self.hex})'

DEFAULT_KEYBITS = 64

parser = argparse.ArgumentParser()
parser.add_argument(
    "-b",
    "--bits",
    type=int,
    default=DEFAULT_KEYBITS,
    help="size of message in bits (must be a multiple of 8)",
)
parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    help="show intermediate steps in fscx_revolve",
)

#Creates a random BitArray object of size bitlength
def new_rand_bitarray(bitlength: int) -> BitArray:
	"""Return a random `BitArray` of *bitlength* bits."""
	result = BitArray(bitlength)
	result.uint = randbits(bitlength)
	return result

#fscx(a,b) = (a ^ b ^ rol(a) ^ rol(b) ^ ror(a) ^ ror(b))
def fscx(A: BitArray, B: BitArray, keybits: int) -> BitArray:
	"""Perform one FSCX transformation."""
	a = A.copy()
	b = B.copy()
	result = a ^ b
	a.ror(1)
	b.ror(1)
	result ^= a ^ b
	a.rol(2)
	b.rol(2)
	result ^= a ^ b
	return result

#Iterative version of fscx
def fscx_revolve(A: BitArray, B: BitArray, keybits: int, steps: int, verbose: bool = False) -> BitArray:
    result = A
    for n in range(steps):
        prev = result
        result = fscx(result, B, keybits)
        if verbose:
            print(f"---FSCX_REVOLVE_PRINT UP:{prev} DOWN:{B} Step {n + 1}: {result}")
    return result

def fscx_revolve_n(A: BitArray, B: BitArray, nonce: BitArray, keybits: int, steps: int, verbose: bool = False) -> BitArray:
    """Nonce-augmented FSCX_REVOLVE (v1.1). Each step: result = fscx(result,B) XOR nonce."""
    result = A.copy()
    for n in range(steps):
        prev = result
        result = fscx(result, B, keybits) ^ nonce
        if verbose:
            print(f"---FSCX_REVOLVE_N_PRINT UP:{prev} DOWN:{B} Step {n + 1}: {result}")
    return result

def main ():
	args = parser.parse_args()
	if args.bits:
		keybits = int(args.bits)
		print (f"Selected key size in bits: {keybits}")
		if int(args.bits) % 8 != 0:
			raise TypeError("Key size in bits must be a multiple of 8!")
	else:
		keybits = int(DEFAULT_KEYBITS)
		print (f"Default key size in bits: {keybits}")
	if args.verbose:
		verbose = True
		print (f"Selected verbose output")
	else:
		verbose = False
		print (f"Default, non-verbose output")

	pubkeybits = int(keybits / 4 * 3)
	privkeybits = int(keybits - pubkeybits)
	print (f"Pub key size in bits: {pubkeybits}")
	print (f"Priv key size in bits: {privkeybits}")

	A = new_rand_bitarray(keybits)
	B = new_rand_bitarray(keybits)
	A2 = new_rand_bitarray(keybits)
	B2 = new_rand_bitarray(keybits)

	print(f"--- Herradura Key Exchange (HKEX) ---\n")
	print(f"ALICE:")
	print(f"{A} A [Secret 1]")
	print(f"{B} B [Secret 2]")
	D=fscx_revolve(A,B,keybits,pubkeybits,verbose) #for 64 keybits, 63 and 31 pubkeybits are weak; 3/4 or 1/4 seems best.
	print(f"{D} [FSCX_REVOLVE(A,B,{pubkeybits})] ->")
	print(f"    BOB:")
	print(f"    A2 {A2} [Secret 3]")
	print(f"    B2 {B2} [Secret 4]")
	D2=fscx_revolve(A2,B2,keybits,pubkeybits,verbose)
	print(f" <- D2 {D2} [FSCX_REVOLVE(A2,B2,{pubkeybits})]")
	hkex_nonce = D ^ D2
	print(f"{hkex_nonce} hkex_nonce [D xor D2]")
	print(f"ALICE:")
	FA=fscx_revolve_n(D2,B,hkex_nonce,keybits,privkeybits,verbose)^A #---for 64 keybits, 1 and 33 pubkeybits are weak; 1 - pubkeybits seems best.
	print(f"{FA} FA [FSCX_REVOLVE_N(D2,B,{privkeybits}) xor A]")
	print(f"    BOB:")
	FA2=fscx_revolve_n(D,B2,hkex_nonce,keybits,privkeybits,verbose)^A2
	if FA == FA2:
		print(f"    FA2 == FA {FA2} [FSCX_REVOLVE_N(D,B2,{privkeybits}) xor A2]")
	else:
		print(f"    Error: FA2 != FA!")

'''
	#Simple exchange test:

	print (f"A={A}, B={B}, fscx(A,B) = {C}")
	C = fscx_revolve(A,B,keybits,pubkeybits,verbose)
	print (f"A={A}, B={B}, fscx_revolve(A,B,{pubkeybits}) = {C}")
	D = fscx_revolve(C,B,keybits,privkeybits,verbose)
	print (f"C={C}, B={B}, fscx_revolve(A,B,{privkeybits}) = {D}")
'''

if __name__ == "__main__":
	main()
