#include <stdio.h>

#include "sodium.h"

int main() {
  #define MESSAGE (const unsigned char *) "test"
  #define MESSAGE_LEN 4
  #define ADDITIONAL_DATA (const unsigned char *) "123456"
  #define ADDITIONAL_DATA_LEN 6

  unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
  unsigned char ciphertext[MESSAGE_LEN + crypto_aead_xchacha20poly1305_ietf_ABYTES];
  unsigned long long ciphertext_len;

  crypto_aead_chacha20poly1305_keygen(key);
  randombytes_buf(nonce, sizeof nonce);

  crypto_aead_chacha20poly1305_encrypt(
    ciphertext, &ciphertext_len,
    MESSAGE, MESSAGE_LEN,
    ADDITIONAL_DATA, ADDITIONAL_DATA_LEN,
    NULL, nonce, key);

  unsigned char decrypted[MESSAGE_LEN];
  unsigned long long decrypted_len;
  if (crypto_aead_chacha20poly1305_decrypt(
    decrypted, &decrypted_len,
    NULL,
    ciphertext, ciphertext_len,
    ADDITIONAL_DATA,
    ADDITIONAL_DATA_LEN,
    nonce, key) 
  == 0) {
    printf("Success\n");
  }
  else {
    printf("Failure\n");
  }
}
