
#include"toy.h"

// toy Post-Quantum Public-Key Cryptosystem
#define NEG(X) (TK_Q - (X))

static void toy_fill_small(short *buf, int n)
{
    for (int k = 0; k < n; ++k)
    {
        short val = rand() & 3;
        val = (val >> 1 & 1) - (val & 1);
        if (val < 0)
            val += TK_Q;
        buf[k] = val;
    }
}

// Naive polynomial multiplication in Z97[X]/(X^4+1)
static void toy_polmul_naive(short *dst, const short *a, const short *b, int add)
{
    dst[0] = ((dst[0] & -add) + a[0] * b[0] + NEG(a[3]) * b[1] + NEG(a[2]) * b[2] + NEG(a[1]) * b[3]) % TK_Q;
    dst[1] = ((dst[1] & -add) + a[1] * b[0] + a[0] * b[1] + NEG(a[3]) * b[2] + NEG(a[2]) * b[3]) % TK_Q;
    dst[2] = ((dst[2] & -add) + a[2] * b[0] + a[1] * b[1] + a[0] * b[2] + NEG(a[3]) * b[3]) % TK_Q;
    dst[3] = ((dst[3] & -add) + a[3] * b[0] + a[2] * b[1] + a[1] * b[2] + a[0] * b[3]) % TK_Q;
}

static void toy_mulmv(short *dst, const short *mat, const short *vec)
{
    memset(dst, 0, TK_K * TK_N * sizeof(short));
    for (int kv = 0, idx = 0; kv < TK_K * TK_N; kv += TK_N)
    {
        for (int k = 0; k < TK_K * TK_N; k += TK_N, idx += TK_N)
            toy_polmul_naive(dst + kv, mat + idx, vec + k, 1);
    }
}

static void toy_mulmTv(short *dst, const short *mat, const short *vec)
{
    memset(dst, 0, TK_K * TK_N * sizeof(short));
    for (int kv = 0; kv < TK_K * TK_N; kv += TK_N)
    {
        for (int k = 0; k < TK_K * TK_N; k += TK_N)
            toy_polmul_naive(dst + kv, mat + TK_K * k + kv, vec + k, 1);
    }
}

static void toy_dot(short *dst, const short *v1, const short *v2)
{
    memset(dst, 0, TK_N * sizeof(short));
    for (int k = 0; k < TK_K * TK_N; k += TK_N)
        toy_polmul_naive(dst, v1 + k, v2 + k, 1);
}

static void toy_add(short *dst, const short *v1, const short *v2, int count, int v2_neg)
{
    for (int k = 0; k < count; ++k)
    {
        short val = v2[k];
        if (v2_neg)
            val = NEG(val);
        dst[k] = (v1[k] + val) % TK_Q;
    }
}

void toy_gen_kyber(short *A, short *t, short *s)
{
    short e[TK_K * TK_N];
    for (int k = 0; k < TK_K * TK_K * TK_N; ++k)
        A[k] = rand() % TK_Q;
    toy_fill_small(s, TK_K * TK_N);
    toy_fill_small(e, TK_K * TK_N);
    toy_mulmv(t, A, s); // t=A.s +e
    toy_add(t, t, e, TK_K * TK_N, 0);
}

void toy_enc_kyber(const short *A, const short *t, int plain, short *u, short *v)
{
    short r[TK_K * TK_N], e1[TK_K * TK_N], e2[TK_N];
    toy_fill_small(r, TK_K * TK_N);
    toy_fill_small(e1, TK_K * TK_N);
    toy_fill_small(e2, TK_N);
    toy_mulmTv(u, A, r); // u = AT.r + el
    toy_add(u, u, e1, TK_K * TK_N, 0);
    toy_dot(v, t, r); // v = tT.r + e2 + plainxq/2
    toy_add(v, v, e2, TK_N, 9);
    for (int k = 0; k < TK_N; ++k)
        v[k] = (v[k] + ((TK_Q >> 1) & -(plain >> k & 1))) % TK_Q;
}

int toy_dec_kyber(const short *s, const short *u, const short *v)
{
    short p[TK_N], plain;
    toy_dot(p, s, u);
    toy_add(p, v, p, TK_N, 1);
    plain = 0;
    for (int k = 0; k < TK_N; ++k)
    {
        int val = p[k];
        if (val > TK_Q / 2)
            val -= TK_Q;
        int bit = abs(val) > TK_Q / 4;
        plain |= bit << k;
    }
    return plain;
}
// Function to perform modular multiplication
int mod_mul(int a, int b, int mod) {
    return (a * b) % mod;
}

// NTT function
void ntt(short result[TK_N], const short input[TK_N], const short roots[TK_N][TK_N]) {
    for (int i = 0; i < TK_N; ++i) {
        result[i] = 0;
        for (int j = 0; j < TK_N; ++j) {
            result[i] += mod_mul(input[j], roots[i][j], TK_Q);
            result[i] %= TK_Q;
        }
    }
}
// Function for modular multiplication
int mod_mul(int a, int b, int mod) {
    return ((long long)a * b) % mod;
}

// Function for modular exponentiation
int mod_exp(int base, int exp, int mod) {
    int result = 1;
    while (exp > 0) {
        if (exp % 2 == 1)
            result = mod_mul(result, base, mod);
        base = mod_mul(base, base, mod);
        exp /= 2;
    }
    return result;
}

// Function to find modular inverse
int mod_inv(int a, int mod) {
    for (int x = 1; x < mod; x++) {
        if (mod_mul(a, x, mod) == 1) {
            return x;
        }
    }
    return -1; // Should not happen for prime mod
}

// Bit reversal permutation
void permute_bitreverse(short *data, short *x) {
    x[0] = data[0];
    x[1] = data[2];
    x[2] = data[1];
    x[3] = data[3];
}

// Fast NTT implementation
void fast_ntt(short *data, int forward) {
    short x[TK_N];
    permute_bitreverse(data, x);

    // Anti-cyclic correction for m(x) = X^n + 1
    int w = forward ? SQRT_W : mod_inv(SQRT_W, TK_Q);
    for (int i = 0; i < TK_N; ++i) {
        int factor = mod_exp(w, i, TK_Q);
        x[i] = mod_mul(x[i], factor, TK_Q);
    }

    // Main NTT computation
    for (int s = 1; s <= log2(TK_N); ++s) {
        int m = 1 << s;
        int w_m = mod_exp(W, TK_N / m, TK_Q);  // Root of unity for this stage
        if (!forward) {
            w_m = mod_inv(w_m, TK_Q);  // Use inverse for iNTT
        }
        for (int k = 0; k < TK_N; k += m) {
            int factor = 1;
            for (int j = 0; j < m / 2; ++j) {
                int a = x[k + j];
                int b = mod_mul(x[k + j + m / 2], factor, TK_Q);
                x[k + j] = (a + b) % TK_Q;
                x[k + j + m / 2] = (a - b + TK_Q) % TK_Q;
                factor = mod_mul(factor, w_m, TK_Q);
            }
        }
    }

    // Copy x back to data
    for (int i = 0; i < TK_N; ++i) {
        data[i] = x[i];
    }
}

