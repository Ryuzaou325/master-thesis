/*int ascon_aead_encrypt(uint8_t* t, uint8_t* c, const uint8_t* m, uint64_t mlen,
    const uint8_t* ad, uint64_t adlen, const uint8_t* npub,
    const uint8_t* k);
int ascon_aead_decrypt(uint8_t* m, const uint8_t* t, const uint8_t* c,
    uint64_t clen, const uint8_t* ad, uint64_t adlen,
    const uint8_t* npub, const uint8_t* k);
*/

#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>  // For __rdtsc()
#include "libs/ascon/ascon/tests/crypto_aead.h" // For Ascon encryption and decryption

#define MESSAGE_LEN 8  // 64-bit (8 bytes) message
#define KEY_LEN 16
#define NONCE_LEN 16
#define ADD_LEN 0
#define TAG_LEN 16

#include <stdint.h>

int main() {
        uint8_t key[KEY_LEN] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        
        uint8_t nonce[NONCE_LEN] = {
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
            0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
        };
    
        uint8_t plaintext[MESSAGE_LEN] = {
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48  // "ABCDEFGH"
        };
    
        uint8_t ciphertext[MESSAGE_LEN + TAG_LEN];  // Encrypted message + authentication tag
        uint8_t decrypted[MESSAGE_LEN];
        unsigned long long clen;
        uint64_t start, end;
    
        /*printf("Plaintext: ");
        for (size_t i = 0; i < MESSAGE_LEN; i++) {
            printf("%02X ", plaintext[i]);
        }
        printf("\n");*/
    
        // Measure encryption cycles
        // start = __rdtsc();
        crypto_aead_encrypt(ciphertext, &clen, plaintext, MESSAGE_LEN, NULL, ADD_LEN, NULL, nonce, key);
        // end = __rdtsc();
        
        /*
        
        printf("Ciphertext: ");
        for (size_t i = 0; i < MESSAGE_LEN + TAG_LEN; i++) {
            printf("%02X ", ciphertext[i]);
        }
        printf("\n");
    
        printf("Encryption time (cycles): %llu\n", (end - start));
  
        */
        // Decryption and Integrity Check
        unsigned long long decrypted_len;
        int result;
    
        // start = __rdtsc();
        result = crypto_aead_decrypt(decrypted, &decrypted_len, NULL, ciphertext, clen, NULL, ADD_LEN, nonce, key);
        // end = __rdtsc();
        
        /*
        
        if (result == 0) {
            printf("Decryption successful!\n");
            printf("Decrypted text: ");
            for (size_t i = 0; i < MESSAGE_LEN; i++) {
                printf("%02X ", decrypted[i]);
            }
            printf("\n");
        } else {
            printf("Decryption failed! Integrity check failed.\n");
        }
    
        printf("Decryption time (cycles): %llu\n", (end - start));
        
        */
    
        return 0;
}
