#include <stdio.h>
#include <sodium.h>

// Function to print a byte in binary form
void print_binary(unsigned char byte) {
    for (int i = 7; i >= 0; i--) {
        printf("%d", (byte >> i) & 1);  // Shift each bit and print it
    }
}

// Manual XOR operation between two buffers
void xor_buffers(unsigned char *buf1, const unsigned char *buf2, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf1[i] ^= buf2[i];  // Perform XOR on each byte
    }
}

int main() {
    // Initialize Libsodium
    if (sodium_init() < 0) {
        printf("Libsodium initialization failed\n");
        return -1;
    }

    // Define two buffers (arrays) of equal length
    unsigned char buf1[] = {0x1F, 0x2A, 0x3B, 0x4C};
    unsigned char buf2[] = {0x4C, 0x3B, 0x2A, 0x1F};

    // Print the original buffers in binary form
    printf("buf1: ");
    for (size_t i = 0; i < sizeof(buf1); i++) {
        print_binary(buf1[i]);
        printf(" ");
    }
    printf("\n");

    printf("buf2: ");
    for (size_t i = 0; i < sizeof(buf2); i++) {
        print_binary(buf2[i]);
        printf(" ");
    }
    printf("\n");

    // Perform XOR of buf1 and buf2, storing the result in buf1 (using our custom xor_buffers function)
    xor_buffers(buf1, buf2, sizeof(buf1));

    // Print the result after XOR operation in binary form
    printf("XOR : ");
    for (size_t i = 0; i < sizeof(buf1); i++) {
        print_binary(buf1[i]);
        printf(" ");
    }
    printf("\n");

    return 0;
}

