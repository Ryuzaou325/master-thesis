#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <x86intrin.h>  // Intrinsics for RDTSC
#include "SNOW_3G.h"
#include "f8.h"
#include "f9.h"

int main() {
    u8 key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    u32 count = 0x389B7B12;
    u32 bearer = 0x15;
    u32 dir = 1;
    u8 data[32] = "This is a test message!";
    u64 length = strlen((char*)data) * 8;
    uint64_t start, end;

    printf("Original Data: %s\n", data);

    /* Measure UEA2 Encryption Time */
    start = __rdtsc();
    f8(key, count, bearer, dir, data, length);
    end = __rdtsc();
    printf("Encrypted Data: %s\n", data);
    printf("UEA2 Encryption Cycles: %lu\n", end - start);

    /* Measure UEA2 Decryption Time (Reapplying f8) */
    start = __rdtsc();
    f8(key, count, bearer, dir, data, length);
    end = __rdtsc();
    printf("Decrypted Data: %s\n", data);
    printf("UEA2 Decryption Cycles: %lu\n", end - start);

    /* Measure UIA2 MAC Computation Time */
    start = __rdtsc();
    u8 *mac = f9(key, count, 0x11223344, dir, data, length);
    end = __rdtsc();
    printf("Generated MAC: %02X%02X%02X%02X\n", mac[0], mac[1], mac[2], mac[3]);
    printf("UIA2 MAC Generation Cycles: %lu\n", end - start);

    return 0;
}
