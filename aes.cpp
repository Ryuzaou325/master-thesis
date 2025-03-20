// code.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

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

	/*
	CryptoPP::SHA1 sha1;
	std::string source = "Hello";
	std::string hash = "";
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));
	std::cout << hash;
	*/
using namespace CryptoPP;

int main() {
    // Key and IV setup
    AutoSeededRandomPool rng;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    SecByteBlock iv(AES::BLOCKSIZE);
    rng.GenerateBlock(iv, iv.size());

    std::string plaintext = "m";

    std::cout << "Plaintext Hex: " << plaintext << std::endl;

    std::string hexOut;
    std::string ciphertext, decryptedtext;
    std::string mac;
    
    try {
        unsigned long long start, end;
        start = __rdtsc(); // Get the initial tick count

        // Encrypt and generate MAC, then verify and decrypt
        GCM<AES>::Encryption encryption;
        encryption.SetKeyWithIV(key, key.size(), iv, sizeof(iv));
        
        StringSource ss(plaintext, true,
            new AuthenticatedEncryptionFilter(encryption,
                new StringSink(ciphertext)
            )
        );
        
        end = __rdtsc(); // Get the final tick count
        
        std::cout << "Encryption clock cycles: " << (end - start) << std::endl;
        
        start = __rdtsc();
        
        /*
        // Calculate MAC separately
        const size_t macSize = 12; // GCM MAC size
        mac.assign(ciphertext.end() - macSize, ciphertext.end());
        */

        // GCM decryption and MAC verification
        GCM<AES>::Decryption decryption;
        decryption.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

        StringSource ss2(ciphertext, true,
            new AuthenticatedDecryptionFilter(decryption,
                new StringSink(decryptedtext)//,
                //AuthenticatedDecryptionFilter::DEFAULT_FLAGS, macSize
            ) // AuthenticatedDecryptionFilter
        ); // StringSource

        // Your code here
        end = __rdtsc();
        std::cout << "Decryption clock cycles: " << (end - start) << std::endl;

    } catch (const CryptoPP::Exception& ex) {
        std::cerr << "Verification failed: " << ex.what() << std::endl;
    }


    // Print the ciphertext and MAC

    hexOut.clear();
    StringSource(ciphertext, true, new HexEncoder(new StringSink(hexOut)));
    std::cout << "Cipher + MAC: " << hexOut << std::endl;

    hexOut.clear();
    StringSource(mac, true, new HexEncoder(new StringSink(hexOut)));
    std::cout << "MAC: " << hexOut << std::endl;

    hexOut.clear();
    StringSource(key, key.size(), true,
        new HexEncoder(new StringSink(hexOut))
        );
    std::cout << "Key: " << hexOut << std::endl;

    hexOut.clear();
    StringSource(iv, iv.size(), true,
        new HexEncoder(new StringSink(hexOut))
    );
    std::cout << "IV: " << hexOut << std::endl;

    std::cout << "Decryption: " << decryptedtext << std::endl;

    return 0;
}

std::string bytesToHex(const byte* data, size_t size) {
	std::string hex;
	CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hex));
	encoder.Put(data, size);
	encoder.MessageEnd();
	return hex;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
