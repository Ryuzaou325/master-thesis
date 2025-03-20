/*---------------------------------------------------------
 *     f8.c
 *---------------------------------------------------------*/
#include "f8.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* f8: Confidentiality Algorithm (UEA2)
 * 
 * Input:
 *   - key: 128-bit Confidentiality Key.
 *   - count: 32-bit Count, Frame dependent input.
 *   - bearer: 5-bit Bearer identity (in the LSB side).
 *   - dir: 1-bit, direction of transmission.
 *   - data: Input bit stream.
 *   - length: 32-bit Length, i.e., the number of bits to be encrypted/decrypted.
 *
 * Output:
 *   - data: Output bit stream (in-place encryption/decryption).
 *
 * Description:
 *   Encrypts/decrypts blocks of data between 1 and 2^32 bits in length 
 *   as defined in Section 3 of the specification.
 */
void f8(u8 *key, u32 count, u32 bearer, u32 dir, u8 *data, u32 length) {
    u32 K[4], IV[4];
    int n = (length + 31) / 32;
    int i = 0;
    u32 *KS;

    /* Initialisation */
    /* Load the confidentiality key for SNOW 3G initialization as in Section 3.4 */
    for (i = 0; i < 4; i++) {
        K[3 - i] = (key[4 * i] << 24) ^ (key[4 * i + 1] << 16) ^ 
                   (key[4 * i + 2] << 8) ^ (key[4 * i + 3]);
    }

    /* Prepare the Initialization Vector (IV) for SNOW 3G as in Section 3.4 */
    IV[3] = count;
    IV[2] = (bearer << 27) | ((dir & 0x1) << 26);
    IV[1] = IV[3];
    IV[0] = IV[2];

    /* Run SNOW 3G algorithm to generate keystream */
    Initialize(K, IV);
    KS = (u32 *)malloc(4 * n);
    GenerateKeystream(n, (u32 *)KS);

    /* Exclusive-OR the input data with keystream to generate the output bit stream */
    for (i = 0; i < n; i++) {
        data[4 * i + 0] ^= (u8)((KS[i] >> 24) & 0xff);
        data[4 * i + 1] ^= (u8)((KS[i] >> 16) & 0xff);
        data[4 * i + 2] ^= (u8)((KS[i] >> 8) & 0xff);
        data[4 * i + 3] ^= (u8)(KS[i] & 0xff);
    }

    /* Free allocated memory */
    free(KS);
}

/* End of f8.c */
