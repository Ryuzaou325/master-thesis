#include <stdio.h>

#include "sodium.h"

int main() {
	if (sodium_init() < 0) {
		printf("libsodium initialization failed");
		return -1;
	}

	unsigned char key[crypto_aead_chacha20poly1305_KEYBYTES];
	unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
	randombytes_buf(key, sizeof(key));
	randombytes_buf(nonce, sizeof(nonce));

	unsigned char plaintext[] = "This is some data to encrypto";
	unsigned char ad[] = "associated data";

	unsigned char ciphertext[sizeof(plaintext) + crypto_aead_chacha20poly1305_ABYTES];
	unsigned char tag[crypto_aead_chacha20poly1305_ABYTES];

	// Encrypt data
	if (crypto_aead_chacha20poly1305_encrypt(
				ciphertext,
				NULL,
				plaintext,
				sizeof(plaintext),
				ad,
				sizeof(ad)
				NULL,
				nonce,
				key) 
			!= 0) {
		printf("Encryption failed");
		return -1;
	}

	printf("Encrypted ciphertext: ");
	for (size_t i = 0; i < sizeof(ciphertext); i++) {
		printf("%02x", ciphertext[i]);
	}
	printf("\n");

	// Decrypt data
	unsigned char decrypted[sizeof(plaintext)];
	unsigned long long decrypted_len;
	if (crypto_aead_chacha20poly1305_decrypt(
				decrypted,
				&decrypted_len,
				NULL,
				ciphertext,
				sizeof(siphertext),
				ad,
				sizeof(ad),
				nonce,
				key
				) != 0) {
		printf("Decryption failed, likely tag mismatch");
	}

	printf("Decryption result: /%s\n", decrypted);
	return 0;
}
