/*  Herradura - a Key exchange scheme in the style of Diffie-Hellman Key Exchange.
    Copyright (C) 2017-2018 Omar Alejandro Herrera Reyna

    This program is free software: you can redistribute it and/or modify
    it under the terms of the MIT License or the GNU General Public License 
    as published by the Free Software Foundation, either version 3 of the License, 
    or (at your option) any later version.

    Under the terms of the GNU General Public License, please also consider that:

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    golang implementation by Russ Magee (rmagee_at_gmail.com) */
package main

import (
	"flag"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

var (
	s int //MUST be 2^n where n is an integer
	p int //Amount of bits to share (a,a,b,b2)
)

// This type holds the session state for a key exchange
type HerraduraKEx struct {
	intSz, pubSz int
	randctx      *rand.Rand
	a, a2, b, b2 big.Int
	fa, fa2      big.Int
}

// Returns a new HerraduraKEx struct
func NewKEx(i int, p int) (h *HerraduraKEx) {
	h = new(HerraduraKEx)

	h.randctx = rand.New(rand.NewSource(42))
	h.intSz = i
	h.pubSz = p
	return h
}

func (h *HerraduraKEx) bitX(x big.Int, pos int) (ret int64) {
	if pos < 0 {
		pos = h.intSz - pos
	}

	if pos == 0 {
		ret = int64(x.Bit(1) ^ x.Bit(0) ^ x.Bit(h.intSz-1))
	} else if pos == h.intSz-1 {
		ret = int64(x.Bit(0) ^ x.Bit(pos) ^ x.Bit(pos-1))
	} else {
		ret = int64(x.Bit((pos+1)%h.intSz) ^ x.Bit(pos) ^ x.Bit(pos-1))
	}
	return ret
}

func (h *HerraduraKEx) bit(up, down big.Int, posU, posD int) (ret *big.Int) {
	return big.NewInt(h.bitX(up, posU) ^ h.bitX(down, posD))
}

func (h *HerraduraKEx) FSCX(up, down big.Int) (result big.Int) {
	result = *big.NewInt(0)

	for count := 0; count < h.intSz; count++ {
		result.Lsh(&result, 1)
		result.Add(&result, h.bit(up, down, count, count))
	}
	return result
}

// This is the iteration function using the result of the previous iteration as the first
// parameter and the second parameter of the first iteration
func (h *HerraduraKEx) FSCXRevolve(up, down *big.Int, passes int) (result big.Int) {
	//	result big.Int

	result = *up
	for count := 0; count < passes; count++ {
		result = h.FSCX(result, *down)
	}
	return result
}

func (h *HerraduraKEx) Seed() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	h.randctx = r
}

func (h *HerraduraKEx) rand() (v *big.Int) {
	v = big.NewInt(0)
	v.Rand(h.randctx /*big.NewInt(42)*/, h.getMax())
	return v
}

// Return max value for an n-bit big.Int
func (h *HerraduraKEx) getMax() (v *big.Int) {
	v = big.NewInt(0)
	var max big.Int

	for i := 0; i < h.intSz; i++ {
		max.SetBit(v, i, 1)
	}
	v = &max
	return v
}

func main() {
	flag.IntVar(&s, "s", 256, "Size in bits of secret (fa,fa2)")
	flag.IntVar(&p, "p", 64, "Size in bits of shared public portion (b,b2)")
	flag.Parse()

	fmt.Printf("s=%v p=%v\n", s, p)

	hkex := NewKEx(s, p)

	hkex.Seed()

	hkex.a = *hkex.rand()
	hkex.b = *hkex.rand()
	hkex.a2 = *hkex.rand()
	hkex.b2 = *hkex.rand()

	fmt.Println("ALICE:")
	fmt.Printf("0x%s A [Secret 1]\n", hkex.a.Text(16))
	fmt.Printf("0x%s B [Secret 2]\n", hkex.b.Text(16))
	d := hkex.FSCXRevolve(&hkex.a, &hkex.b, hkex.pubSz)
	fmt.Printf("0x%s D [FSCXRevolve(A,B,%d)] -> \n", d.Text(16), hkex.pubSz)

	fmt.Println("\t\t\t\t   BOB:")
	fmt.Printf("\t\t\t\t   A2 0x%s [Secret 3]\n", hkex.a2.Text(16))
	fmt.Printf("\t\t\t\t   B2 0x%s [Secret 4]\n", hkex.b2.Text(16))
	d2 := hkex.FSCXRevolve(&hkex.a2, &hkex.b2, hkex.pubSz)
	fmt.Printf("\t\t\t\t<- D2 0x%s [FSCXRevolve(A2,B2,%d)]\n", d2.Text(16), hkex.pubSz)
	
	hkex.fa = hkex.FSCXRevolve(&d2, &hkex.b, hkex.intSz - hkex.pubSz)
	hkex.fa.Xor(&hkex.fa, &hkex.a)
	fmt.Printf("0x%s FA [FSCXRevolve(D2,B,%d) xor A]\n", hkex.fa.Text(16), hkex.intSz - hkex.pubSz)
	
	hkex.fa2 = hkex.FSCXRevolve(&d, &hkex.b2, hkex.intSz - hkex.pubSz)
	hkex.fa2.Xor(&hkex.fa2, &hkex.a2)
	fmt.Printf("\t\t\t\t FA = FA2 0x%s [FSCXRevolve(D,B2,%d) xor A2]\n", hkex.fa2.Text(16), hkex.intSz - hkex.pubSz)
}
