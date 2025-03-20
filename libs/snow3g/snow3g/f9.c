/*---------------------------------------------------------
 *     f9.c
 *---------------------------------------------------------*/
#include "f9.h"
#include <stdio.h>
#include <math.h>
#include <string.h>

/* MUL64x.
 * Input: 
 *   - V: a 64-bit input.
 *   - c: a 64-bit input.
 * Output:
 *   - A 64-bit output.
 *   - A 64-bit memory is allocated which is to be freed by the calling function.
 * Description:
 *   Performs a left shift and conditional XOR operation based on the MSB.
 *   See section 4.3.2 for details.
 */
u64 MUL64x(u64 V, u64 c) {
    if (V & 0x8000000000000000)
        return (V << 1) ^ c;
    else
        return V << 1;
}

/* MUL64xPOW.
 * Input:
 *   - V: a 64-bit input.
 *   - i: a positive integer.
 *   - c: a 64-bit input.
 * Output:
 *   - A 64-bit output.
 *   - A 64-bit memory is allocated which is to be freed by the calling function.
 * Description:
 *   Recursively performs multiple MUL64x operations.
 *   See section 4.3.3 for details.
 */
u64 MUL64xPOW(u64 V, u8 i, u64 c) {
    if (i == 0)
        return V;
    else
        return MUL64x(MUL64xPOW(V, i - 1, c), c);
}

/* MUL64.
 * Input:
 *   - V: a 64-bit input.
 *   - P: a 64-bit input.
 *   - c: a 64-bit input.
 * Output:
 *   - A 64-bit output.
 *   - A 64-bit memory is allocated which is to be freed by the calling function.
 * Description:
 *   Computes the multiplication operation in the finite field.
 *   See section 4.3.4 for details.
 */
u64 MUL64(u64 V, u64 P, u64 c) {
    u64 result = 0;
    int i = 0;

    for (i = 0; i < 64; i++) {
        if ((P >> i) & 0x1)
            result ^= MUL64xPOW(V, i, c);
    }
    return result;
}

/* mask8bit.
 * Input:
 *   - n: an integer in the range [1,7].
 * Output:
 *   - An 8-bit mask.
 * Description:
 *   Prepares an 8-bit mask with the required number of 1 bits on the MSB side.
 */
u8 mask8bit(int n) {
    return 0xFF ^ ((1 << (8 - n)) - 1);
}

/* f9: Integrity Algorithm (UIA2)
 * Input:
 *   - key: 128-bit Integrity Key.
 *   - count: 32-bit Count, Frame dependent input.
 *   - fresh: 32-bit Random number.
 *   - dir: 1-bit, direction of transmission (in the LSB).
 *   - data: Input bit stream.
 *   - length: 64-bit Length, i.e., the number of bits to be MAC'd.
 * Output:
 *   - A 32-bit block used as MAC.
 * Description:
 *   Generates a 32-bit MAC using the UIA2 algorithm as defined in Section 4.
 */
u8* f9(u8* key, u32 count, u32 fresh, u32 dir, u8 *data, u64 length) {
    u32 K[4], IV[4], z[5];
    u32 i = 0, D;
    static u8 MAC_I[4] = {0, 0, 0, 0}; /* Static memory for the result */
    u64 EVAL, V, P, Q, c, M_D_2;
    int rem_bits = 0;

    /* Load the Integrity Key for SNOW 3G initialization as in section 4.4. */
    for (i = 0; i < 4; i++)
        K[3 - i] = (key[4 * i] << 24) ^ (key[4 * i + 1] << 16) ^ 
                   (key[4 * i + 2] << 8) ^ (key[4 * i + 3]);

    /* Prepare the Initialization Vector (IV) for SNOW 3G initialization as in section 4.4. */
    IV[3] = count;
    IV[2] = fresh;
    IV[1] = count ^ (dir << 31);
    IV[0] = fresh ^ (dir << 15);

    /* Initialize keystream words */
    z[0] = z[1] = z[2] = z[3] = z[4] = 0;

    /* Run SNOW 3G to produce 5 keystream words z_1, z_2, z_3, z_4 and z_5. */
    Initialize(K, IV);
    GenerateKeystream(5, z);

    P = ((u64)z[0] << 32) | (u64)z[1];
    Q = ((u64)z[2] << 32) | (u64)z[3];

    /* Calculation */
    D = (length % 64 == 0) ? (length >> 6) + 1 : (length >> 6) + 2;
    EVAL = 0;
    c = 0x1b;

    /* Process message blocks */
    for (i = 0; i < D - 2; i++) {
        V = EVAL ^ ((u64)data[8 * i] << 56 | (u64)data[8 * i + 1] << 48 |
                    (u64)data[8 * i + 2] << 40 | (u64)data[8 * i + 3] << 32 |
                    (u64)data[8 * i + 4] << 24 | (u64)data[8 * i + 5] << 16 |
                    (u64)data[8 * i + 6] << 8  | (u64)data[8 * i + 7]);
        EVAL = MUL64(V, P, c);
    }

    /* Process last block */
    rem_bits = length % 64;
    if (rem_bits == 0)
        rem_bits = 64;

    M_D_2 = 0;
    i = 0;
    while (rem_bits > 7) {
        M_D_2 |= (u64)data[8 * (D - 2) + i] << (8 * (7 - i));
        rem_bits -= 8;
        i++;
    }

    if (rem_bits > 0)
        M_D_2 |= (u64)(data[8 * (D - 2) + i] & mask8bit(rem_bits)) << (8 * (7 - i));

    V = EVAL ^ M_D_2;
    EVAL = MUL64(V, P, c);

    /* Process final block */
    EVAL ^= length;

    /* Multiply by Q */
    EVAL = MUL64(EVAL, Q, c);

    /* Store result */
    for (i = 0; i < 4; i++)
        MAC_I[i] = (EVAL >> (8 * (3 - i))) & 0xff;

    return MAC_I;
}

/* End of f9.c */
/*------------------------------------------------------------------------*/
