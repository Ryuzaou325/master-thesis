#include <stdio.h>

#include "sodium.h"

int main() {
  #define MESSAGE (const unsigned char *) "test"
  #define MESSAGE_LEN 4
  #define ADDITIONAL_DATA (const unsigned char *) "123456"
  #define ADDITIONAL_DATA_LEN 6

  unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
  unsigned char key[crypto_aead_chacha20poly1305_KEYBYTES];
  unsigned char ciphertext[MESSAGE_LEN + crypto_aead_chacha20poly1305_ABYTES];
  unsigned char buffer[1024];
  unsigned long long ciphertext_len = sizeof(ciphertext);
  
  printf("message: %s\n", sodium_bin2base64(buffer, sizeof(buffer), MESSAGE, MESSAGE_LEN, sodium_base64_VARIANT_ORIGINAL));
  
  printf("aad: %s\n", sodium_bin2base64(buffer, sizeof(buffer), ADDITIONAL_DATA, ADDITIONAL_DATA_LEN, sodium_base64_VARIANT_ORIGINAL));

  crypto_aead_chacha20poly1305_keygen(key);
  randombytes_buf(nonce, sizeof nonce);
  
  crypto_aead_chacha20poly1305_encrypt(ciphertext, &ciphertext_len,
    MESSAGE, MESSAGE_LEN,
    ADDITIONAL_DATA, ADDITIONAL_DATA_LEN,
    NULL, nonce, key);
    
  printf("ciphertext: %s\n", sodium_bin2base64(buffer, sizeof(buffer), ciphertext, sizeof(ciphertext), sodium_base64_VARIANT_ORIGINAL));

  unsigned char decrypted[MESSAGE_LEN];
  unsigned long long decrypted_len = MESSAGE_LEN;
  if (crypto_aead_chacha20poly1305_decrypt(
    decrypted, &decrypted_len,
    NULL,
    ciphertext, ciphertext_len,
    ADDITIONAL_DATA, ADDITIONAL_DATA_LEN,
    nonce, key) 
  == 0) {
    printf("succes, descrypted: %s\n", sodium_bin2base64(buffer, sizeof(buffer), decrypted, sizeof(decrypted), sodium_base64_VARIANT_ORIGINAL));
  }
  else {
    printf("failed, decrypted: %s\n", sodium_bin2base64(buffer, sizeof(buffer), decrypted, MESSAGE_LEN, sodium_base64_VARIANT_ORIGINAL));
  }
}
