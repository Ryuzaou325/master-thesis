/*int ascon_aead_encrypt(uint8_t* t, uint8_t* c, const uint8_t* m, uint64_t mlen,
    const uint8_t* ad, uint64_t adlen, const uint8_t* npub,
    const uint8_t* k);
int ascon_aead_decrypt(uint8_t* m, const uint8_t* t, const uint8_t* c,
    uint64_t clen, const uint8_t* ad, uint64_t adlen,
    const uint8_t* npub, const uint8_t* k);
*/

#include <stdio.h>
#include <stdint.h>
#include <sodium.h>
#include "./../libs/ascon/ascon/tests/crypto_aead.h" // For Ascon encryption and decryption

#define NONCE_LEN 16

void ascon(uint8_t *message, int message_length, uint8_t *additional_data, int additional_data_length, int mac_length, uint8_t *key) {
    
    uint8_t nonce[16];
    randombytes_buf(nonce, sizeof nonce);
    
    uint8_t ciphertext[message_length + mac_length];
    uint8_t decrypted[message_length];
    
    unsigned long long clen;
    crypto_aead_encrypt(ciphertext, &clen, message, message_length, additional_data, additional_data_length, NULL, nonce, key);
    unsigned long long decrypted_len;
    int result = crypto_aead_decrypt(decrypted, &decrypted_len, NULL, ciphertext, clen, additional_data, additional_data_length, nonce, key);
    
    if (result != 0) {
        printf("ERROR: Integrity check failed in Ascon");
    }
    
}

/*
int main(int argc, char *argv[]) {
    ascon(argv[1], atoi(argv[2]), argv[3], atoi(argv[4]), atoi(argv[5]), argv[6]);
}
*/
