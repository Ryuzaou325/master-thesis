#include <string.h>
#include <stdio.h>


#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <x86intrin.h>

#include "libs/SipHash/SipHash/halfsiphash.h"

int main() {
    uint8_t key[8] = { 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78 };
    // Define a 32-bit (4-byte) message
    uint8_t data[4] = { 0x12, 0x34, 0x56, 0x78 };
    uint8_t hash_out[4]; // Output buffer

    __asm__ volatile("cpuid" ::: "rax", "rbx", "rcx", "rdx");
  
    // Measure start time (cycles)
    uint64_t start = __rdtsc();  
    for (int i = 0; i < 1000000; i++) {
    // Run the HalfSipHash function
    halfsiphash(data, sizeof(data), key, hash_out, sizeof(hash_out));
    }
    // Measure end time (cycles)
    uint64_t end = __rdtsc();
  
    __asm__ volatile("cpuid" ::: "rax", "rbx", "rcx", "rdx");
  
    // Compute total cycles used
    uint64_t total_cycles = end - start;
  
    // Print the results
    
    printf("CPU Cycles: %llu\n", total_cycles);
    printf("Hash: ");
    for (size_t i = 0; i < sizeof(hash_out); i++) {
        printf("%02x", hash_out[i]);
    }
    printf("\n");
    printf("\n");
    return 0;
  }
