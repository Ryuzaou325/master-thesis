#include <iostream>
#include <string>
#include <aes.h>
#include <gcm.h>
#include <filters.h>
#include <hex.h>
#include <osrng.h>

using namespace CryptoPP;
using namespace std;

int main()
{
    // Generate a random key and IV (nonce)
    AutoSeededRandomPool prng;

    // 256-bit key (uint8_t instead of CryptoPP::byte)
    uint8_t key[AES::DEFAULT_KEYLENGTH];
    prng.GenerateBlock(key, sizeof(key));

    // 128-bit IV (nonce)
    uint8_t iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    // Message to encrypt
    string plain = "This is a test message for AES-GCM encryption!";

    // GCM encryption
    string cipher, recovered;
    try
    {
        // AES-GCM encryption
        GCM<AES>::Encryption encryption;
        encryption.SetKeyWithIV(key, sizeof(key), iv);

        // Add additional authenticated data (AAD) if needed
        string aad = "Some additional data";
        encryption.SpecifyDataLengths(aad.size(), plain.size(), 0);

        // Encrypt the message
        StringSource(plain, true,
                     new AuthenticatedEncryptionFilter(encryption,
                                                        new StringSink(cipher),
                                                        false,  // Don't include the MAC in the output
                                                        new StringSource(aad, true, NULL)  // AAD
                     ));

        // Output the ciphertext in hexadecimal format
        cout << "Cipher Text (Hex): ";
        StringSource(cipher, true,
                     new HexEncoder(new FileSink(cout)));
        cout << endl;

        // GCM decryption
        GCM<AES>::Decryption decryption;
        decryption.SetKeyWithIV(key, sizeof(key), iv);

        // Specify the same AAD for decryption
        decryption.SpecifyDataLengths(aad.size(), cipher.size(), 0);

        // Decrypt the message
        StringSource(cipher, true,
                     new AuthenticatedDecryptionFilter(decryption,
                                                       new StringSink(recovered),
                                                       false,  // Don't check the MAC
                                                       new StringSource(aad, true, NULL)  // AAD
                     ));

        // Output the recovered plaintext message
        cout << "Recovered Text: " << recovered << endl;
    }
    catch (const Exception& e)
    {
        cerr << "Error: " << e.what() << endl;
    }

    return 0;
}

