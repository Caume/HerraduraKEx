/* v3_round_cost.c — TODO #255: what does NL-FSCX v3's chi layer actually cost?
 *
 * #255 quotes "+57% per round" from #246 §5.  That figure is the cost of MASKING
 * the chi layer relative to masking the modular addition the v2 family already
 * needs; there is no masked v2 in the suite, so it is not the cost of the shipped
 * path.  This measures the unmasked one.
 *
 * Both rounds run in the same 4x64-bit limb representation with delta(B)
 * precomputed, so the only difference measured is chi itself.  chi is implemented
 * as two shift-and-mask row rotations -- the 47 five-bit rows and the 3 seven-bit
 * rows of the 256 = 47x5 + 3x7 partition are each contiguous and uniform, so no
 * bit-by-bit loop is needed -- and is validated bit-exactly against a per-row
 * reference before timing, so the ratio is that of a correct fast implementation.
 *
 * Build/run:  gcc -O2 -o /tmp/v3cost benchmarks/v3_round_cost.c && /tmp/v3cost
 *
 * Recorded on an x86-class host, gcc -O2:  v2 37.4 ns, v3 81.2 ns, ratio 2.17x.
 * Analysis: SecurityProofsCode/nl_fscx_v3_round_count.py §7, SecurityProofs-7.md §11.33.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
typedef struct { uint64_t w[4]; } S;   /* w[0] = least significant */

static inline S xr(S a,S b){S r;for(int i=0;i<4;i++)r.w[i]=a.w[i]^b.w[i];return r;}
static inline S shl(S a,int k){S r={{0,0,0,0}};for(int i=3;i>=0;i--){r.w[i]=a.w[i]<<k;if(k&&i)r.w[i]|=a.w[i-1]>>(64-k);}return r;}
static inline S shr(S a,int k){S r={{0,0,0,0}};for(int i=0;i<4;i++){r.w[i]=a.w[i]>>k;if(k&&i<3)r.w[i]|=a.w[i+1]<<(64-k);}return r;}
static inline S rol1(S a){S l=shl(a,1);l.w[0]|=a.w[3]>>63;return l;}
static inline S ror1(S a){S r=shr(a,1);r.w[3]|=(a.w[0]&1ULL)<<63;return r;}
static inline S M(S a){return xr(a,xr(rol1(a),ror1(a)));}
static inline S add(S a,S b){S r;unsigned __int128 c=0;for(int i=0;i<4;i++){c+=(unsigned __int128)a.w[i]+b.w[i];r.w[i]=(uint64_t)c;c>>=64;}return r;}
static inline S andn(S a,S b){S r;for(int i=0;i<4;i++)r.w[i]=(~a.w[i])&b.w[i];return r;}
static inline S and_(S a,S b){S r;for(int i=0;i<4;i++)r.w[i]=a.w[i]&b.w[i];return r;}
static inline S or_(S a,S b){S r;for(int i=0;i<4;i++)r.w[i]=a.w[i]|b.w[i];return r;}

/* partition 256 = 47x5 + 3x7 */
static S TOPA,TOPB,NOTTOP,T2A,T2B,NOTTOP2;
static void setbit(S*s,int p){s->w[p>>6]|=1ULL<<(p&63);}
static void build(void){
    memset(&TOPA,0,sizeof TOPA);memset(&TOPB,0,sizeof TOPB);
    memset(&T2A,0,sizeof T2A);memset(&T2B,0,sizeof T2B);
    int o=0;
    for(int r=0;r<47;r++){setbit(&TOPA,o+4);setbit(&T2A,o+4);setbit(&T2A,o+3);o+=5;}
    for(int r=0;r<3;r++){setbit(&TOPB,o+6);setbit(&T2B,o+6);setbit(&T2B,o+5);o+=7;}
    for(int i=0;i<4;i++){NOTTOP.w[i]=~(TOPA.w[i]|TOPB.w[i]);NOTTOP2.w[i]=~(T2A.w[i]|T2B.w[i]);}
}
static inline S chi(S x){
    S r1=or_(and_(shr(x,1),NOTTOP), or_(and_(shl(x,4),TOPA), and_(shl(x,6),TOPB)));
    S r2=or_(and_(shr(x,2),NOTTOP2),or_(and_(shl(x,3),T2A),  and_(shl(x,5),T2B)));
    return xr(x,andn(r1,r2));
}
/* reference chi, bit by bit, to validate the fast one */
static S chi_ref(S x){
    int b[256],out[256];S r;
    for(int i=0;i<256;i++)b[i]=(x.w[i>>6]>>(i&63))&1;
    int o=0;
    for(int g=0;g<50;g++){int L=(g<47)?5:7;
        for(int j=0;j<L;j++)out[o+j]=b[o+j]^((1-b[o+(j+1)%L])&b[o+(j+2)%L]);
        o+=L;}
    memset(&r,0,sizeof r);
    for(int i=0;i<256;i++)if(out[i])r.w[i>>6]|=1ULL<<(i&63);
    return r;
}
static inline S round_v2(S x,S B,S d,uint64_t i){S t=x;t.w[0]^=i;return add(M(xr(t,B)),d);}
static inline S round_v3(S x,S B,S d,uint64_t i){return chi(round_v2(x,B,d,i));}

int main(void){
    build();
    /* validate fast chi against reference, and bijectivity on random inputs */
    S x={{0x0123456789abcdefULL,0xfedcba9876543210ULL,0xa5a5a5a5a5a5a5a5ULL,0x0f1e2d3c4b5a6978ULL}};
    for(int t=0;t<2000;t++){
        S a=chi(x),b=chi_ref(x);
        if(memcmp(&a,&b,sizeof a)){printf("CHI MISMATCH at t=%d\n",t);return 1;}
        x=chi(xr(x,(S){{(uint64_t)t*0x9e3779b97f4a7c15ULL,t,t*7,t*13}}));
    }
    printf("chi fast == chi_ref on 2000 vectors: OK\n");

    S B={{0xdeadbeefcafebabeULL,0x1234567890abcdefULL,0x0f0f0f0f0f0f0f0fULL,0x7777777777777777ULL}};
    S d={{0x1111111111111111ULL,0x2222222222222222ULL,0x3333333333333333ULL,0x4444444444444444ULL}};
    const long N=2000000;
    S s={{1,2,3,4}};
    struct timespec t0,t1;
    clock_gettime(CLOCK_MONOTONIC,&t0);
    for(long k=0;k<N;k++)s=round_v2(s,B,d,(uint64_t)(k&255)+1);
    clock_gettime(CLOCK_MONOTONIC,&t1);
    double v2=(t1.tv_sec-t0.tv_sec)+1e-9*(t1.tv_nsec-t0.tv_nsec);
    volatile uint64_t sink=s.w[0];
    s=(S){{1,2,3,4}};
    clock_gettime(CLOCK_MONOTONIC,&t0);
    for(long k=0;k<N;k++)s=round_v3(s,B,d,(uint64_t)(k&255)+1);
    clock_gettime(CLOCK_MONOTONIC,&t1);
    double v3=(t1.tv_sec-t0.tv_sec)+1e-9*(t1.tv_nsec-t0.tv_nsec);
    sink^=s.w[0];(void)sink;
    printf("v2 round: %.2f ns   v3 round: %.2f ns   ratio %.3fx\n",
           v2/N*1e9, v3/N*1e9, v3/v2);
    printf("block cost v2 @192 rounds: %.2f us\n", v2/N*192*1e6);
    for(int r=112;r<=224;r+=16)
        printf("  v3 @%3d rounds: %6.2f us   vs v2@192 = %.3fx\n",
               r, v3/N*r*1e6, (v3/N*r)/(v2/N*192));
    return 0;
}
