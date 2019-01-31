/*  Herradura AEn (HAEN)- an asymmetric, one to one, cipher based on the FSCX function and 
    parameters from a previous Key Exchange with Herradura KEx (HKEX).
    
    Copyright (C) 2017-2019 Omar Alejandro Herrera Reyna

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
    along with this program.  If not, see <https://www.gnu.org/licenses/>. */

/* Example build: gcc -DINTSZ=64 -o HAEN Herradura_AEn.c */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <assert.h>

typedef unsigned long long int INT64;

#undef VERBOSE

#ifndef INTSZ
  #define INTSZ 64 // MUST be 2^n where n is an integer
  #warning *** INTSZ defaulting to 64  ***
#endif

#ifndef PUBSIZE
  #define PUBSIZE 16   // How much is shared by Alice, Bob (D, D2)
  #warning *** PUBSIZE defaulting to 16 ***
#endif

#if INTSZ == 8
#define INTSZMASK 0x0FF
#elif INTSZ == 16
#define INTSZMASK 0x0FFFF
#elif INTSZ == 32
#define INTSZMASK 0x0FFFFFFFF
#elif INTSZ == 64
#define INTSZMASK 0xFFFFFFFFFFFFFFFF
#else
#define INTSZMASK 0
#error *** UNSUPPORTED INTSZ ***
#endif

#ifdef VERBOSE /*rlm*/
void print64b (INT64 x){
  int cont;
  unsigned long int y1,y2,tmp;
  y1=(unsigned long int) x;
  x = x >> 32;
  y2=(unsigned long int) x;
  for (cont=0;cont<32;cont++){
    tmp= y2 & 0x80000000;
    if (tmp == 0x80000000){
      printf("1");
    }
    else{
      printf("0");
    }
    y2 = y2<<1;
  }
  for (cont=0;cont<32;cont++){
    tmp= y1 & 0x80000000;
    if (tmp == 0x80000000){
      printf("1");
    }
    else{
      printf("0");
    }
    y1 = y1<<1;
  }
}
#endif

/*Generate pseudorandom 64bit numbers with rand()*/ 
INT64 rnd64b (){
  INT64 rnd64;
  unsigned long int tmp,cont;
  rnd64=0;
  for (cont=0;cont<3;cont++){
    tmp = rand();
    rnd64 = rnd64+(INT64)tmp;
    rnd64 = rnd64<<16;
  };
  tmp = rand();
  rnd64 = rnd64 +(INT64) tmp;
  return(rnd64);
}

unsigned int BITX(INT64 X, int pos) {
  if( pos == 0 ) {
    return ((X>>1)&1) ^ (X&1) ^ ((X>>(INTSZ-1))&1);
  }
  else if( pos == (int)INTSZ-1 ) {
    return (X&1) ^ ((X>>(INTSZ-1))&1) ^ ((X>>(INTSZ-2))&1);
  }
  else {
    return ((X>>((pos+1)%INTSZ))&1) ^ ((X>>pos)&1) ^ ((X>>((pos-1)%INTSZ))&1);
  }
}

unsigned int BIT(INT64 U, INT64 D, int posU, int posD) {
  unsigned int ret = BITX(U, posU) ^ BITX(D, posD);
  return ret;
}

/* Full Surroundings Cyclic XOR (FSCX) */
INT64 FSCX (const INT64 *Up, INT64 *Down){
  INT64 result = 0;
  int count;

  for(count = 0; count < (int)INTSZ; count++) {
    result = result<<1;
#if INTSZ < 64
    result &= INTSZMASK;
#endif
    // NOTE the algo appears to work even using mismatched counts for U,D here
    result += (INT64)BIT(*Up, *Down, count, count);
    //result += (INT64)BIT(*Up, *Down, count, (INTSZ-1u)-count);
#if INTSZ < 64
    result &= INTSZMASK;
#endif
  }
  return result;
}

/*FSCX iteration function using the result of the previous iteration as the first
  parameter and the second parameter of the first iteration*/
INT64 FSCX_REVOLVE (INT64 *Up, INT64 *Down, unsigned long int pasos){
    INT64 result;
    unsigned long int cont;
    result=*Up;
    for (cont=0; cont<pasos; cont++){
        result=FSCX(&result,Down);
    }
    return result;
}

#ifdef VERBOSE /*rlm*/
/* FSCX iteration function that prints each step */
INT64 FSCX_REVOLVE_PRINT (INT64 *Up, INT64 *Down, unsigned long int pasos){
    INT64 result,first;
    unsigned long int cont;
    result=*Up;
    first=result;
    for (cont=0; cont<pasos; cont++){
        result=FSCX(&first,Down);
        printf("     FSCX_REVOLVE_PRINT UP:%llu DOWN:%llu Step %lu:%llu\n",first,*Down,cont+1,result);
        first=result;
    }
    return (result);
}
#endif

int main (){
  INT64 A,A2,B,B2,D,D2,FA,FA2,PSV,K,P,P2,E;
  srand(time(0));

  P=rnd64b();
  A=rnd64b();
  B=rnd64b();
  A2=rnd64b();
  B2=rnd64b();
#if INTSZ < 64u
  P &= INTSZMASK;
  A &= INTSZMASK;
  A2 &= INTSZMASK;
  B &= INTSZMASK;
  B2 &= INTSZMASK;
#endif
  printf("--- Herradura Key Exchange (HKEX) ---\n\n");
  printf("ALICE:\n");
  printf("%llx A [Secret 1]\n",A);
  printf("%llx B [Secret 2]\n",B);
  D=FSCX_REVOLVE(&A,&B,PUBSIZE);   //63 and 32 rounds are weak; 16 seems best.
  printf("%llx D [FSCX_REVOLVE(A,B,%u)] ->\n",D, PUBSIZE);
  printf("    BOB:\n");
  printf("    A2 %llx [Secret 3]\n",A2);
  printf("    B2 %llx [Secret 4]\n",B2);
  D2=FSCX_REVOLVE(&A2,&B2,PUBSIZE);  //63 and 32 rounds are weak; 16 seems best.
  printf(" <- D2 %llx [FSCX_REVOLVE(A2,B2,%u)]\n",D2, PUBSIZE);
  printf("ALICE:\n");
  FA=(FSCX_REVOLVE(&D2,&B,(INTSZ-PUBSIZE)))^A;
  printf("%llx FA [FSCX_REVOLVE(D2,B,%u) xor A] \n",FA, (INTSZ-PUBSIZE));
  printf("    BOB:\n");
  FA2=(FSCX_REVOLVE(&D,&B2,(INTSZ-PUBSIZE)))^A2;
  assert(FA == FA2);
  printf("    FA2 = FA %llx [FSCX_REVOLVE(D,B2,%u) xor A2] \n",FA2, (INTSZ-PUBSIZE));

  printf("\n\n--- Herradura one-to-one asymmetric Encryption - keys of same size & interactive KEX Alice,Bob(HAEN1) ---\n\n");
  PSV=FA;
  /*Alice's encryption key is: PSV,A,B,PUBSIZE */
  printf("ALICE [ 1 to 1 assymetric key with Bob = PSV,A,B,PUBSIZE]:\n");
  printf("%llx PSV [Pre-shared key value from KEX (FA)]\n",PSV);
  printf("%llx A [Secret from KEX]\n",A);
  printf("%llx B [Secret from KEX]\n",B);
  printf("%llx P [MSG in plain text]\n",P);
  K=P^PSV^A;
  E=FSCX_REVOLVE(&K,&B,PUBSIZE);
  printf("%llx E [Shared encrypted MSG, FSCX_REVOLVE(P xor PSV xor A, B ,%u)] ->\n",E,PUBSIZE);
  
  /*Bob's decryption key is: PSV,A2,B2,(INTSZ - PUBSIZE) */
  /*  (Strictly speaking, when PSV = FA and FA comes from previous HKEX using A,B,A2,B2, you 
       don't need PSV to decrypt) */       
  printf("    BOB [ 1 to 1 assymetric key with Alice = PSV,A2,B2,(INTSZ - PUBSIZE)]:\n");
  printf("    PSV %llx [Pre-shared key from KEX (FA2)]\n",PSV);
  printf("    A2 %llx [Secret from KEX]\n",A2);
  printf("    B2 %llx [Secret from KEX]\n",B2);
  P2=(FSCX_REVOLVE(&E,&B2,INTSZ-PUBSIZE))^A2;  
  printf("    P2 %llx [MSG in plain text, FSCX_REVOLVE(E,B2,%u) xor A2] \n",P2,INTSZ-PUBSIZE);
  assert(P == P2);

  /* Note: you can use a different preshared value (i.e. not from KEX), but in that case you still 
     need the entangled parameters from a previous KEX: B,B2 and FA; decryption would be as follows:
 
  P2=(FSCX_REVOLVE(&E,&B2,INTSZ-PUBSIZE))^PSV2^A2^FA2;
  printf("    P2 %llx [Shared secret MSG in plain text, FSCX_REVOLVE(E,B2,%u) xor PSV2 xor A2 xor FA2] \n",P2,INTSZ-PUBSIZE);
 
  */
  
  printf("\n\n--- Herradura one-to-one assymetric key encryption - keys of different size & KEX done by Bob (HAEN2) ---\n\n");
  PSV=FA;
  /*Here Bob performs KEX on its own, then shares the entangled key with Alice through other means */  
  /*Alice's encryption key is: PSV,B,PUBSIZE */
  printf("ALICE [ 1 to 1 assymetric (smaller) key with Bob = PSV,B,PUBSIZE]:\n");
  printf("%llx PSV [shared key by Bob (alternate channel)]\n",PSV);
  printf("%llx B [shared secret by Bob (alternate channel)]\n",B);
  printf("%llx P [MSG in plain text]\n",P);
  K=P^PSV;
  E=FSCX_REVOLVE(&K,&B,PUBSIZE);
  printf("%llx E [Shared encrypted MSG, FSCX_REVOLVE(P xor PSV, B ,%u)] ->\n",E,PUBSIZE);
  
  /*Bob's decryption key is: PSV,A,A2,B2,(INTSZ - PUBSIZE) */
  /*  (Strictly speaking, when PSV = FA and FA comes from previous HKEX using A,B,A2,B2, you 
       don't need PSV to decrypt) */       
  printf("    BOB [ 1 to 1 assymetric (bigger) key with Alice = PSV,A,A2,B2,(INTSZ - PUBSIZE)]:\n");
  printf("    PSV %llx [Key from KEX calculated by Bob (FA2)]\n",PSV);
  printf("    A  %llx [Secret from KEX]\n",A);
  printf("    A2 %llx [Secret from KEX]\n",A2);
  printf("    B2 %llx [Secret from KEX]\n",B2);
  P2=(FSCX_REVOLVE(&E,&B2,INTSZ-PUBSIZE))^A^A2;  
  printf("    P2 %llx [MSG in plain text, FSCX_REVOLVE(E,B2,%u) xor A xor A2] \n",P2,INTSZ-PUBSIZE);
  assert(P == P2);

  /* Note: you can use a different preshared value (i.e. not from KEX), but in that case you still 
     need the entangled parameters from a previous KEX: B,B2 and FA; decryption would be as follows:
  
  P2=(FSCX_REVOLVE(&E,&B2,INTSZ-PUBSIZE))^PSV2^A^A2^FA2;
  printf("    P2 %llx [Shared secret MSG in plain text, FSCX_REVOLVE(E,B2,%u) xor PSV2 xor A xor A2 xor FA2] \n",P2,INTSZ-PUBSIZE);
  
  */

  return (0);
}
