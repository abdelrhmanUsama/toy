
#include "toy.h"

int main()
{
    // Initialize seed
    srand(1234);

    // Declare variables
    short A[TK_K * TK_K * TK_N], t[TK_K * TK_N], s[TK_K * TK_N];
    short u[TK_K * TK_N], v[TK_N];
    int plain, decrypted;

    // Key generation
    toy_gen_kyber(A, t, s);

    // Test cases with different plaintexts
    int test_plaintexts[] = {1, 2, 15, 8, 11, 7, 0};
    int num_tests = sizeof(test_plaintexts) / sizeof(test_plaintexts[0]);

    for (int i = 0; i < num_tests; i++)
    {
        plain = test_plaintexts[i];

        // Encryption
        toy_enc_kyber(A, t, plain, u, v);

        // Decryption
        decrypted = toy_dec_kyber(s, u, v);

        // Print results
        printf("\nTest Case %d\n", i + 1);
        printf("Original plaintext: %d\n", plain);
        printf("Decrypted plaintext: %d\n", decrypted);
    }
        int w = 22;
    int sqrt_w = 33;
    int q = 97;

    int w_to_4 = w * w * w * w % q;
    int sqrt_w_to_2 = sqrt_w * sqrt_w % q;

    printf("22^4 mod 97 = %d\n", w_to_4);
    printf("33^2 mod 97 = %d\n", sqrt_w_to_2);


    return 0;
}
