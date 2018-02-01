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
    along with this program.  If not, see <https://www.gnu.org/licenses/>. */

/* Example build: gcc -DINTSZ=64 -o demo_bignum Herradura_demo_bignum.c -lgmp */

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
INT64 FSCX (const INT64 const *Up, INT64 *Down){
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
  INT64 A,A2,L,L2,B,B2,C,D,D2,FA,FA2,Q,R,G,K;
  unsigned long int tmp,cont,brk;
  srand(time(0));

  A=rnd64b();
  B=rnd64b();
  A2=rnd64b();
  B2=rnd64b();
#if INTSZ < 64u
  A &= INTSZMASK;
  A2 &= INTSZMASK;
  B &= INTSZMASK;
  B2 &= INTSZMASK;
#endif

  printf("ALICE:\n");
  printf("%llx A [Secret 1]\n",A);
  printf("%llx B [Secret 2]\n",B);
  D=FSCX_REVOLVE(&A,&B,PUBSIZE);   //63 and 32 rounds are weak; 16 seems best.
  printf("%llx D [FSCX_REVOLVE(A,B,%u)] ->\n",D, PUBSIZE);

  printf("\t\t\t\t   BOB:\n");
  printf("\t\t\t\t   A2 %llx [Secret 3]\n",A2);
  printf("\t\t\t\t   B2 %llx [Secret 4]\n",B2);
  D2=FSCX_REVOLVE(&A2,&B2,PUBSIZE);  //63 and 32 rounds are weak; 16 seems best.
  printf("\t\t\t\t<- D2 %llx [FSCX_REVOLVE(A2,B2,%u)]\n",D2, PUBSIZE);

  FA=(FSCX_REVOLVE(&D2,&B,(INTSZ-PUBSIZE)))^A;
  printf("%llx FA [FSCX_REVOLVE(D2,B,%u) xor A] \n",FA, (INTSZ-PUBSIZE));

  FA2=(FSCX_REVOLVE(&D,&B2,(INTSZ-PUBSIZE)))^A2;

  assert(FA == FA2);

  printf("\t\t\t\t FA = FA2 %llx [FSCX_REVOLVE(D,B2,%u) xor A2] \n",FA2, (INTSZ-PUBSIZE));

#ifdef VERBOSE /*rlm*/
//NOTE: Only D and D2 (Exchanged by Alice and Bob) are known to EVE:  
  printf("\n--- EVE tests to determine one of the secrets of Alice or Bob:\n");
  printf("\n");
  printf("EVE: NOT (D xor D2)= %llu \n",~(D^D2));
  printf("EVE: D xor D2= %llu \n",D^D2);
  printf("EVE: FSCX(D,D2)= %llu \n",FSCX(&D,&D2));
  printf("EVE: FSCX(D2,D)= %llu \n",FSCX(&D2,&D));
  printf("EVE: FSCX(D,D2) xor D= %llu \n",FSCX(&D,&D2)^D);
  printf("EVE: FSCX(D2,D) xor D= %llu \n",FSCX(&D2,&D)^D);
  printf("EVE: FSCX_REVOLVE_PRINT(D,D2,64)= %llu\n",FSCX_REVOLVE_PRINT(&D,&D2,64));
  printf("EVE: FSCX_REVOLVE_PRINT(D2,D,64)= %llu\n",FSCX_REVOLVE_PRINT(&D2,&D,64));
  printf("\nExample FSCX_REVOLVE(%llu,%llu,16)=%llu:\n",A,B,FSCX_REVOLVE(&A,&B,16));
  print64b(A);
  printf("\n");
  print64b(B);
  printf("\n");
  print64b(FSCX_REVOLVE(&A,&B,16));
  printf("\n");

  printf("\nExample2 FSCX_REVOLVE(%llu,%llu,16)=%llu:\n",A2,B2,FSCX_REVOLVE(&A2,&B2,16));
  print64b(A2);
  printf("\n");
  print64b(B2);
  printf("\n");
  print64b(FSCX_REVOLVE(&A2,&B2,16));
  printf("\n");

  printf("\n--- FSCX() features\n");
  printf("\n");
  printf("A: %llu\n",A);
  print64b(A);
  printf("\n");
  printf("B: %llu\n",B);
  print64b(B);
  printf("\n");
  K=FSCX(&A,&B);
  printf("%llu [FSCX(A,B)]\n",K);
  G=FSCX(&B,&A);
  printf("%llu [FSCX(B,A)]\n",G);
  L=FSCX(&K,&B);
  printf("%llu [FCSX(FSCX(A,B),B)]\n",L);
  L=FSCX(&A,&K);
  printf("%llu [FCSX(A,FSCX(A,B))]\n",L);

  //Note: depending on the numbers selected, it may take 32 or 64 steps to get back A
  printf("\n--- FSCX revolve:\n");
  printf("%llu A  \n",A);
  printf("%llu B  \n",B);
  K=FSCX(&A,&B);
  printf("step 1: %llu K  [FSCX(A,B)]\n",K);
  for (cont=2; cont< 257; cont++){
	K=FSCX(&K,&B);
	printf("step %lu: %llu K  [FSCX(K,B)]\n",cont,K);
	if (K==A){
		printf("! step %lu: A == K\n",cont);
	}
    if (K==B){
		printf("! step %lu: B == K\n",cont);
	}
  }

//xoring can't just happen at any point
  printf("\n--- FSCX revolve + xor after steps 1,64:\n");
  C=rnd64b();
  printf("%llu A  \n",A);
  printf("%llu B  \n",B);
  printf("%llu C  \n",C);
  K=FSCX(&A,&B);
  L=K^C;
  printf("step 1: %llu K [FSCX(A,B)]\n",K);
  printf("step 1: %llu L [FSCX(A,B) xor C]\n",L);
  for (cont=2; cont< 257; cont++){
	L=FSCX(&L,&B);
    if (cont == 64){ 
        L=L^C;
        printf("step %lu: %llu L [FSCX(L,B) xor C]\n",cont,L);
    } else {
        printf("step %lu: %llu L [FSCX(L,B)]\n",cont,L);
    }        
	if (L==A){
		printf("! step %lu: A == L\n",cont);
	}
    if (L==B){
		printf("! step %lu: B == L\n",cont);
	}
  }

//But you can xor on each step and get back A
  printf("\n--- FSCX revolve + xor after each step:\n");
  A=rnd64b();
  B=rnd64b();
  C=rnd64b();
  printf("%llu A  \n",A);
  printf("%llu B  \n",B);
  printf("%llu C  \n",C);
  K=FSCX(&A,&B);
  L=K^C;
  printf("step 1: %llu K [FSCX(A,B)]\n",K);
  printf("step 1: %llu L [FSCX(A,B) xor C]\n",L);
  for (cont=2; cont< 257; cont++){
	L=(FSCX(&L,&B))^C;
    printf("step %lu: %llu L  [FSCX(L,B) xor C]\n",cont,L);
	if (L==A){
		printf("! step %lu: A == L\n",cont);
	}
    if (L==B){
		printf("! step %lu: B == L\n",cont);
	}
  }

//Optional EVE´s slow brute force test
/*
  printf("EVE brute force attack demo...\n");
  brk = 1;
  while (brk){
      Q=rnd64b();
      for (R=0; R < ULLONG_MAX - 1; R++){
          if ((FSCX_REVOLVE(&Q,&R,16))==D){
              printf("Got it! FSCX_REVOLVE(%llu,%llu,16)==D(%llu)\n",Q,R,D);
              brk=0;
              break;
          }
      }            
  }
  printf("--END EVE brute force attack demo...\n");
*/
#endif /* VERBOSE */

  return (0);
}
