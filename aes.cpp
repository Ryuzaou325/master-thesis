#include <aes.h>
#include <gcm.h>
#include <filters.h>
#include <osrng.h>
#include <hex.h>
#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include <string>
#include <x86intrin.h>

#pragma intrinsic(__rdtsc)

using namespace CryptoPP;

int main() {
    // Key and IV setup
    AutoSeededRandomPool rng;

    // AES key and IV as uint8_t arrays
    uint8_t key[AES::DEFAULT_KEYLENGTH];
    rng.GenerateBlock(key, sizeof(key));

    uint8_t iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    // Plaintext as uint8_t array
    uint8_t plaintext[] = {0x33, 0x33, 0x22, 0x22};  // Plaintext array as uint8_t
    size_t plaintextSize = sizeof(plaintext);

    std::cout << "Plaintext: " << plaintext << std::endl;

    // Adjust ciphertext and decryptedtext buffers based on plaintext size
    size_t ciphertextSize = plaintextSize + AES::BLOCKSIZE;  // Include MAC size for GCM
    uint8_t* ciphertext = new uint8_t[ciphertextSize];  // Dynamic buffer for ciphertext
    uint8_t* decryptedtext = new uint8_t[ciphertextSize];  // Dynamic buffer for decrypted text

    try {
        unsigned long long start, end;
        start = __rdtsc(); // Get the initial tick count

        // Encrypt and generate MAC, then verify and decrypt
        GCM<AES>::Encryption encryption;
        encryption.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

        // Prepare ArraySink to hold encrypted data
        ArraySink arraySink(ciphertext, ciphertextSize);

        // StringSource for encryption (using uint8_t array directly)
        StringSource ss(plaintext, plaintextSize, true,
            new AuthenticatedEncryptionFilter(encryption,
                new ArraySink(ciphertext, ciphertextSize)  // Store encrypted data
            )
        );

        end = __rdtsc(); // Get the final tick count
        std::cout << "Encryption clock cycles: " << (end - start) << std::endl;

        start = __rdtsc();

        // GCM decryption and MAC verification
        GCM<AES>::Decryption decryption;
        decryption.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

        ArraySink decryptedArraySink(decryptedtext, ciphertextSize);  // Prepare for decrypted data

        StringSource ss2(ciphertext, ciphertextSize, true,
            new AuthenticatedDecryptionFilter(decryption,
                new ArraySink(decryptedtext, ciphertextSize)  // Store decrypted data
            )
        );

        end = __rdtsc();
        std::cout << "Decryption clock cycles: " << (end - start) << std::endl;

    } catch (const CryptoPP::Exception& ex) {
        std::cerr << "Verification failed: " << ex.what() << std::endl;
    }

    // Print the ciphertext in hexadecimal format
    std::string hexOut;
    StringSource(ciphertext, ciphertextSize, true, 
        new HexEncoder(new StringSink(hexOut))
    );
    std::cout << "Ciphertext (Hex): " << hexOut << std::endl;

    // Print the decrypted text
    hexOut.clear();
    StringSource(decryptedtext, ciphertextSize, true, 
        new HexEncoder(new StringSink(hexOut))
    );
    std::cout << "Decrypted Text (Hex): " << hexOut << std::endl;

    // Clean up dynamically allocated memory
    delete[] ciphertext;
    delete[] decryptedtext;

    return 0;
}

