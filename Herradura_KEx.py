###
#    Herradura KEx (HKEX)- a Key exchange scheme in the style of Diffie-Hellman Key Exchange,
#    based on the FSCX function.
#
#    Copyright (C) 2017-2022 Omar Alejandro Herrera Reyna
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

from bitstring import BitArray
from random import getrandbits
import argparse

DefaultKeybits = 64

parser = argparse.ArgumentParser()
parser.add_argument("-b", "--bits", help = "size of message in bits")
parser.add_argument("-v", "--verbose", help = "if set, the program will show each step in fscx_revolve", action='store_true')

#Creates a random BitArray object of size bitlength
def newRandBitarray (bitlength):
	result = BitArray(bitlength)
	result.uint = getrandbits(bitlength)
	return result

#fscx(a,b) = (a ^ b ^ rol(a) ^ rol(b) ^ ror(a) ^ ror(b))
def fscx(A,B,keybits):
	result = BitArray(keybits)
	result = A ^ B
	A.ror(1)
	B.ror(1)
	result = result ^ A ^ B
	A.rol(2)
	B.rol(2)
	result = result ^ A ^ B
	A.ror(1)	#we need to preserve A and B since BitArrays are mutable.
	B.ror(1)
	return result

#Iterative version of fscx
def fscx_revolve (A,B,keybits,steps,verbose):
	result = BitArray(keybits)
	prevresult = BitArray(keybits)
	result = A
	for n in range(0,steps):
		prevresult = result
		result = fscx(result,B,keybits)
		if (verbose):
			print(f"---FSCX_REVOLVE_PRINT UP:{prevresult} DOWN:{B} Step {n}: {result}")
	return result

def main ():
	args = parser.parse_args()
	if args.bits:
		keybits = int(args.bits)
		print (f"Selected key size in bits: {keybits}")
		if int(args.bits) % 8 != 0:
			raise TypeError("Key size in bits must be a multiple of 8!")
	else:
		keybits = int(DefaultKeybits)
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

	A = newRandBitarray(keybits)
	B = newRandBitarray(keybits)
	A2 = newRandBitarray(keybits)
	B2 = newRandBitarray(keybits)

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
	print(f"ALICE:")
	FA=fscx_revolve(D2,B,keybits,privkeybits,verbose)^A #---for 64 keybits, 1 and 33 pubkeybits are weak; 1 - pubkeybits seems best.
	print(f"{FA} FA [FSCX_REVOLVE(D2,B,{privkeybits}) xor A]")
	print(f"    BOB:")
	FA2=fscx_revolve(D,B2,keybits,privkeybits,verbose)^A2
	if FA == FA2:
		print(f"    FA2 == FA {FA2} [FSCX_REVOLVE(D,B2,{privkeybits}) xor A2]")
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
