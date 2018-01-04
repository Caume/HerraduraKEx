/*  Herradura - a Key exchange scheme in the style of Diffie-Hellman Key Exchange.
    Copyright (C) 2017 Omar Alejandro Herrera Reyna

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>. */

/* gmplib (GNU multi-precision) implementation - Russ Magee (rmagee_at_gmail.com) */
/* Example build: gcc -DINTSZ=256 -o demo_bignum Herradura_demo_bignum.c -lgmp */

#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <time.h>
#include <limits.h>
#include <assert.h>

#ifndef INTSZ
#warning *** INTSZ defaulting to 256 ***
#define INTSZ 256 // MUST be 2^n where n is an integer
#define PUBSIZE 64   // How much is shared by Alice, Bob (D, D2)
#else
#define PUBSIZE (INTSZ/4)
#endif

// At certain points we must mask out accumulators as bignums won't let bits just 'fall off'
// the end when rotating or adding values
mpz_t intszmask;

unsigned int BITX(mpz_t X, int pos) {
  if( pos == 0 ) {
    return mpz_tstbit(X,1) ^ mpz_tstbit(X,0) ^ mpz_tstbit(X,(INTSZ-1));
  }
  else if( pos == INTSZ-1u ) {
    return mpz_tstbit(X,0) ^ mpz_tstbit(X,(INTSZ-1)) ^ mpz_tstbit(X,(INTSZ-2));
  }
  else {
    return mpz_tstbit(X,(pos+1)%INTSZ) ^ mpz_tstbit(X,pos) ^ mpz_tstbit(X,(pos-1)%INTSZ);
  }
}

unsigned int BIT(mpz_t U, mpz_t D, int posU, int posD) {
  return BITX(U, posU) ^ BITX(D, posD);
}

/* Full Surroundings Cyclic XOR (FSCX) */
void FSCX(mpz_t Up, mpz_t Down, mpz_t result) {
  int count;

  mpz_set_ui(result, 0);
  for(count = 0; count < (int)INTSZ; count++) {
    mpz_mul_2exp(result, result, 1); // << 1
    mpz_and(result, result, intszmask); // as bignums don't drop bits shifted up

    // NOTE the algo works using mismatched counts for U,D here
    mpz_add_ui(result, result, BIT(Up, Down, count, count));
    //mpz_add_ui(result, result, BIT(Up, Down, count, INTSZ-1-count));
  }
}

/*FSCX iteration function using the result of the previous iteration as the first
  parameter and the second parameter of the first iteration*/
void FSCX_REVOLVE(mpz_t Up, mpz_t Down, unsigned long int passes, /*out*/ mpz_t result) {
    unsigned long int count;

    mpz_init2(result, INTSZ);
    mpz_set(result, Up);
    mpz_t newResult; mpz_init2(newResult, INTSZ);
    for(count=0u; count < passes; count++) {
        FSCX(result,Down,newResult);
        mpz_set(result, newResult);
    }
}

int main () {
  gmp_randstate_t rndstate;
  gmp_randinit_mt(rndstate);
  gmp_randseed_ui(rndstate, time(0) /*42*/);

  mpz_t A,A2,B,B2,D,D2,FA,FA2;

  mpz_inits(A, A2, B, B2, D, D2, FA, FA2, NULL);

  mpz_init2(intszmask, INTSZ);
  for(int bitidx=0; bitidx < INTSZ; bitidx++) {
    mpz_setbit(intszmask, bitidx);
  }

#undef _TESTVALS

#ifdef _TESTVALS
  mpz_init2(A, INTSZ);
  mpz_set_str(A, "e8829ccaf6450b29", 16); // A [Secret 1]
  mpz_and(A, A, intszmask);

  mpz_init2(B, INTSZ);
  mpz_set_str(B, "56887012e782d9c", 16); // B [Secret 2]
  mpz_and(B, B, intszmask);

  mpz_init2(A2, INTSZ);
  mpz_set_str(A2, "aa07e3d776ba0107", 16); // A2 [Secret 3]
  mpz_and(A2, A2, intszmask);

  mpz_init2(B2, INTSZ);
  mpz_set_str(B2, "b68499f2357dafa2", 16); // B2 [Secret 4]
  mpz_and(B2, B2, intszmask);
#else
  mpz_urandomb(A, rndstate, INTSZ);
  mpz_urandomb(B, rndstate, INTSZ);
  mpz_urandomb(A2, rndstate, INTSZ);
  mpz_urandomb(B2, rndstate, INTSZ);
#endif

  mpz_init2(D, INTSZ);
  mpz_init2(D2, INTSZ);
  mpz_init2(FA, INTSZ);
  mpz_init2(FA2, INTSZ);

  printf("ALICE:\n");
  mpz_out_str(NULL, 16, A); printf(" A [Secret 1]\n");
  mpz_out_str(NULL, 16, B); printf(" B [Secret 2]\n");
  FSCX_REVOLVE(A, B, PUBSIZE, D);
  mpz_out_str(NULL, 16, D); printf(" D [FSCX_REVOLVE(A,B,%u)] ->\n", PUBSIZE);

  printf("\t\t\t\t   BOB:\n");
  printf("\t\t\t\t   A2 "); mpz_out_str(NULL, 16, A2); printf(" [Secret 3]\n");
  printf("\t\t\t\t   B2 "); mpz_out_str(NULL, 16, B2); printf(" [Secret 4]\n");
  FSCX_REVOLVE(A2,B2, PUBSIZE, D2);
  printf("\t\t\t\t<- D2 "); mpz_out_str(NULL, 16, D2); printf(" [FSCX_REVOLVE(A2,B2,%u)]\n", PUBSIZE);

  FSCX_REVOLVE(D2,B,INTSZ-PUBSIZE, FA);
  mpz_xor(FA, A, FA);

  mpz_out_str(NULL, 16, FA); printf(" FA [FSCX_REVOLVE(D2,B,%u) xor A]\n", INTSZ-PUBSIZE);

  FSCX_REVOLVE(D,B2,INTSZ-PUBSIZE, FA2);
  mpz_xor(FA2, A2, FA2);

  printf("\t\t\t\t FA = FA2 ");
  mpz_out_str(NULL, 16, FA2); printf(" [FSCX_REVOLVE(D,B2,%u) xor A2]\n",INTSZ-PUBSIZE);

  assert(mpz_cmp(FA,FA2) == 0);

  return (0);
}
