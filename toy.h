#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include<stdint.h>

#define TK_K 3
#define TK_N 4
#define TK_Q 97
#define W 22
#define SQRT_W 33

void toy_gen_kyber(short *A, short *t, short *s);
int toy_dec_kyber(const short *s, const short *u, const short *v);
void toy_enc_kyber(const short *A, const short *t, int plain, short *u, short *v);
int mod_mul(int a, int b, int mod);
void ntt(short result[TK_N], const short input[TK_N], const short roots[TK_N][TK_N]);
int mod_mul(int a, int b, int mod);
int mod_exp(int base, int exp, int mod);
int mod_inv(int a, int mod); 
void permute_bitreverse(short *data, short *x);
void fast_ntt(short *data, int forward);
