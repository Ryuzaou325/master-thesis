#include <stdio.h>
#include <sodium.h>

int main() {
  #define MESSAGE ((const unsigned char *) "test")
  #define MESSAGE_LEN 4
  #define CIPHERTEXT_LEN (crypto_secretbox_MACBYTES + MESSAGE_LEN)

  unsigned char key[crypto_secretbox_KEYBYTES];
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  unsigned char ciphertext[CIPHERTEXT_LEN];

  crypto_secretbox_keygen(key);
  randombytes_buf(nonce, sizeof nonce);
  crypto_secretbox_easy(ciphertext, MESSAGE, MESSAGE_LEN, nonce, key);

  unsigned char decrypted[MESSAGE_LEN];
  if (crypto_secretbox_open_easy(decrypted, ciphertext, CIPHERTEXT_LEN, nonce, key) == 0) {
    printf("Success\n");
  }
  else {
    printf("Failure\n");
  }
}
