#include <iostream>
#include <iomanip>
#include <cryptlib.h>
#include <threefish.h>
#include <modes.h>        // For ECB_Mode and other cipher modes
#include <filters.h>      // For StreamTransformationFilter and PKCS7_Encoder
#include <x86intrin.h>    // For __rdtsc

using namespace CryptoPP;
using namespace std;

int main() {
    // The key must be exactly 32 bytes for Threefish-256 (256 bits)
    byte key[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 
                    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};

    // Message smaller than block size (e.g., only 16 bytes)
    byte plaintext[16] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
                          0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50};

    // Container for ciphertext and decrypted message
    byte ciphertext[32];  // Make sure to have enough space for the block size
    byte decrypted[32];

    // Print original message
    cout << "Original plaintext: ";
    for (int i = 0; i < sizeof(plaintext); i++) {
        cout << (char)plaintext[i];
    }
    cout << endl;

    try {
        // Create the Threefish256 cipher (256 bit)
        Threefish256::Encryption encryptor;
        encryptor.SetKey(key, sizeof(key));  // Set the key for encryption

        // Set up the ECB mode with PKCS7 padding
        ECB_Mode<Threefish256>::Encryption ecbEncryptor;
        ecbEncryptor.SetKey(key, sizeof(key));

        // Measure encryption time using __rdtsc
        unsigned long long start = __rdtsc();
        StringSource(plaintext, sizeof(plaintext), true, 
            new StreamTransformationFilter(ecbEncryptor,
                new ArraySink(ciphertext, sizeof(ciphertext))));
        unsigned long long end = __rdtsc();
        
        // Show time to encrypt in CPU cycles
        printf("Encryption time in cycles: %llu\n", (end - start));

        // Print encrypted data
        cout << "Encrypted ciphertext (in hex): ";
        for (int i = 0; i < sizeof(ciphertext); i++) {
            cout << hex << setw(2) << setfill('0') << (int)ciphertext[i];
        }
        cout << endl;

        // Decrypt the ciphertext
        ECB_Mode<Threefish256>::Decryption ecbDecryptor;
        ecbDecryptor.SetKey(key, sizeof(key));

        // Measure de cryption time using __rdtsc
        start = __rdtsc();
        StringSource(ciphertext, sizeof(ciphertext), true, 
            new StreamTransformationFilter(ecbDecryptor,
                new ArraySink(decrypted, sizeof(decrypted))));
        end = __rdtsc();
        
        // Show time to decrypt in CPU cycles
        printf("Decryption time in cycles: %llu\n", (end - start));

        // Print decrypted data (should match original plaintext)
        cout << "Decrypted plaintext: ";
        for (int i = 0; i < sizeof(decrypted); i++) {
            cout << (char)decrypted[i];
        }
        cout << endl;

    } catch (const Exception& e) {
        cerr << "Error: " << e.what() << endl;
    }

    return 0;
}

