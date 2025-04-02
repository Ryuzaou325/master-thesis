#define _GNU_SOURCE

// Includes for code
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <unistd.h>
#include <sched.h>
#include <semaphore.h>
#include <pthread.h>

// fork stuff
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>

// cflush
#include <emmintrin.h>

// #include "benchmark-helpers.h"

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <x86intrin.h>
#include <ctype.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

// Libsodium: chacha, poly, aes, hmac
#include <sodium.h>

// siphash
#include "libs/SipHash/SipHash/halfsiphash.h"
#include "libs/SipHash/SipHash/siphash.h"

// 5G standard encryption/authentication
#include "libs/snow3g/snow3g/SNOW_3G.h"
#include "libs/snow3g/snow3g/f8.h"
#include "libs/snow3g/snow3g/f9.h"

#include "metrics/metrics.h"
#include "algorithms/algorithms.h"

#define RDTSC
// #define RAM
// #define PERF

#define KEY_LENGTH 16 // 64 bits
#define IV_LENGTH 16
#define MAC_LENGTH 8
#define ADDITIONAL_DATA_LENGTH 0

#define VERBOSE 0

#define CACHE_LINE_SIZE 64			 // Most CPUs use 64-byte cache lines
#define CACHE_SIZE (8 * 1024 * 1024) // Assume 8MB L3 cache

#define FLUSH_CACHES 0

sem_t mutex;

#define BENCH(name, iterations, initialize, bench)                                                 \
	if (strcmp(argv[1], name) == 0)                                                    \
	{                                                                                  \
		printf("\nRunning a benchmark for %s with %d iterations\n", name, iterations); \
		unsigned long sum = 0;                                                         \
		unsigned long max = 0;                                                         \
		for (int i = 0; i < iterations; i++)                                           \
		{                                                                              \
			if (FLUSH_CACHES) flush_all_caches(); \
			initialize; \
			bench;                                                                     \
			int ram = runRamCheck();                                                   \
			sum += ram;                                                                \
			if (max < ram)                                                             \
				max = ram;                                                             \
		}                                                                              \
		printf("\nAverage RAM Usage: %f Kilobytes\n", ((double)sum / iterations));     \
		printf("Maximum RAM Usage: %ld Kilobytes\n", max);                             \
		sum = 0;                                                                       \
		max = 0;                                                                       \
		for (int i = 0; i < iterations; i++)                                           \
		{                                                                              \
			if (FLUSH_CACHES) flush_all_caches(); \
			initialize; \
			unsigned long long start = __rdtsc();                                      \
			bench;                                                                     \
			unsigned long long end = __rdtsc();                                        \
			sum += (end - start);                                                      \
			if (max < (end - start))                                                   \
				max = (end - start);                                                   \
		}                                                                              \
		printf("\nRDTSC Average Cycle count: %f\n", ((double)sum / iterations));       \
		printf("RDTSC Maximum Cycle count: %ld\n", max);   \
		printf("Cycles per byte: %f\n", (double)(((double)sum / iterations) / (double)MESSAGE_LENGTH)); \
		sum = 0;                                                                       \
		max = 0;                                                                       \
		int ctr = create_perf_event();                                                 \
		for (int i = 0; i < iterations; i++)                                           \
		{                                                                              \
			if (FLUSH_CACHES)                                                          \
				flush_all_caches(); \
			initialize; \
			start_counter(ctr);                                                        \
			bench;                                                                     \
			long long result = stop_counter(ctr);                                      \
			sum += result;                                                             \
			if (max < result)                                                          \
				max = result;                                                          \
		}                                                                              \
		printf("\nPerf Average Instruction count: %f\n", ((double)sum / iterations));  \
		printf("Perf Maximum Instruction count: %ld\n", max);                          \
	}
	
void pin_to_core(int core_id)
{
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(core_id, &cpuset);

	int result = sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
	if (result != 0)
	{
		perror("sched_setaffinity");
	}
}

void printHex(unsigned char *sequence, unsigned int length)
{
	for (int i = 0; i < length; i++)
	{
		printf("%02x", sequence[i]);
	}
	printf("\n");
}

// Flush all cache
void flush_all_caches()
{
	char *buffer = (char *)malloc(CACHE_SIZE);
	if (!buffer)
	{
		perror("Memory allocation failed");
		return;
	}

	for (size_t i = 0; i < CACHE_SIZE; i += CACHE_LINE_SIZE)
	{
		_mm_clflush(&buffer[i]); // Flush each cache line
	}
	_mm_sfence(); // Ensure all flushes complete

	free(buffer);
}

void init(uint8_t *message, int mlen, uint8_t *key, int keylen) {
    randombytes_buf(message, mlen);
    //printHex(message, sizeof(message));
    randombytes_buf(key, keylen);
}

int main(int argc, char *argv[])
{
	pin_to_core(0);

	if (argc < 4)
	{
		printf("Usage: ./benchmark <algorithm name> <iterations> <message length>\n");
		return 1;
	}

	if (argv[2] != NULL && *argv[2] != '\0' && argv[2][0] != '0')
	{
		int i = 0;
		for (i = 0; argv[2][i] != '\0'; i++)
		{
			if (!isdigit((unsigned char)argv[2][0]))
			{
				printf("Invalid iteration input. Must be a positive value not leading with 0 and less than 9999999\n");
				return 1;
			}
		}
		if (i > 7)
		{
			printf("Invalid iteration input. Must be a positive value not leading with 0 and less than 9999999\n");
			return 1;
		}
	}
	else
	{
		printf("Invalid iteration input. Must be a positive value not leading with 0 and less than 9999999\n");
		return 1;
	}

	if (strcmp(argv[1], "siphash") != 0 && strcmp(argv[1], "halfsiphash") != 0 &&
		strcmp(argv[1], "ascon") != 0 && strcmp(argv[1], "uia2") != 0 &&
		strcmp(argv[1], "uea2") != 0 && strcmp(argv[1], "uea2uia2") != 0 &&
		strcmp(argv[1], "chachapoly") != 0 && strcmp(argv[1], "chacha") != 0 &&
		strcmp(argv[1], "poly") != 0 &&
		strcmp(argv[1], "hmac") != 0 && strcmp(argv[1], "aes") != 0 &&
		strcmp(argv[1], "xor") != 0 && strcmp(argv[1], "chachasip") != 0)
	{
		printf("Incorrect algorithm name choice. Options: \nsiphash, halfsiphash, ascon, uia2, uea2, uea2uia2, chachapoly, chacha, poly,  hmac, aes, xor \n");
		return 1;
	}

	// Initializing values. These lengths should be in bytes. Edit as needed;

#define MESSAGE_LENGTH atoi(argv[3])
	
/*
	pid_t pids[iterations];
	int pipefd[iterations][2];
	int maxRam = 0;

	// Initialize pipes
	for (int i = 0; i < iterations; i++) {
		if (pipe(pipefd[i]) == -1) {
			perror("pipe failed");
			exit(EXIT_FAILURE);
		}
	}

  sem_init(&mutex, 0, 1);


	for (int i = 0; i < iterations; i++) {
		pids[i] = fork();
		if (pids[i] == 0) { // Child process
	  sem_wait(&mutex);
	  if(VERBOSE) printf("Thread %d holds the lock\n", i);
			close(pipefd[i][0]); // close read end
			int value = runRDTSC(argv[1], atoi(argv[3]));
			write(pipefd[i][1], &value, sizeof(value));
			close(pipefd[i][1]); // close write end
	  if(VERBOSE) printf("Thread %d releases the lock\n", i);
	  sem_post(&mutex);

			exit(EXIT_SUCCESS);
		} else if (pids[i] < 0) {
			perror("fork failed");
			exit(1);
		}
	}
	int sum = 0;
	int max = 0;
	// parent process collects values
	for (int i = 0; i < iterations; i++) {
		int received_value;
		close(pipefd[i][1]); // close write end on parent
		// read and store value in received_value
		read(pipefd[i][0], &received_value, sizeof(received_value));
		sum += received_value;
		if (max < received_value) max = received_value;
		close(pipefd[i][0]); // close read end
		//printf("Received value = %d\n", received_value);

		waitpid(pids[i], NULL, 0); // wait for child to finish
	}
	printf("Average: %d\n", sum / iterations);
	printf("Maximum: %d\n", max);
	printf("message length: %d\n", atoi(argv[3]));
	printf("Cycles per Byte: %f\n", (float)((float)sum / (float)iterations) / (float)atoi(argv[3]));

  sem_destroy(&mutex);*/
		

    int iterations = atoi(argv[2]);
    uint8_t key[KEY_LENGTH];
    uint8_t polyKey[crypto_onetimeauth_KEYBYTES];
    //printf("%d\n", sizeof(polyKey));
    int8_t integrityKey[8];
    uint8_t message[MESSAGE_LENGTH];
    uint8_t additional_data[ADDITIONAL_DATA_LENGTH];
    u32 count = 0x389B7B12;
    u32 bearer = 0x15;
    uint8_t msgCheck[MESSAGE_LENGTH];

    BENCH("siphash", iterations, {
        init(message, sizeof(message), key, sizeof(key));
    }, {
        sip(message, sizeof(message), key);
    })

    BENCH("halfsiphash", iterations, {
        init(message, sizeof(message), key, sizeof(key));
    }, {
        halfsip(message, sizeof(message), key);
    })

    BENCH("ascon", iterations, {
        init(message, sizeof(message), key, sizeof(key));
        randombytes_buf(additional_data, sizeof(additional_data));
    }, {
        ascon(message, sizeof(message), additional_data, sizeof(additional_data), MAC_LENGTH, key);    
    })

    BENCH("uia2", iterations, {
        init(message, sizeof(message), key, sizeof(key));
    }, {
        // Sender
        uint8_t integrityIv[4];
	randombytes_buf(integrityIv, sizeof integrityIv);
	u8 *hashOut = f9(key, count, (u32)integrityIv, 1, message, sizeof(message));
	// Receiver
	u8 *hashCmp = f9(key, count, (u32)integrityIv, 1, message, sizeof(message));
        if (sizeof(hashOut) != sizeof(hashCmp) || memcmp(hashOut, hashCmp, sizeof(hashOut)) != 0) {
            printf("ERROR: Integrity check failed in uia2");
        }
    })
    BENCH("uea2", iterations, {
        init(message, sizeof(message), key, sizeof(key));
        memcpy(msgCheck, message, sizeof(message));
    }, {
        // Sender
	f8(key, count, bearer, 1, message, sizeof(message));
	// message is now encrypted. reapply to get original message back
	f8(key, count, 0x15, 1, message, sizeof(message));
	//if (sizeof(msgCheck) != sizeof(message) || memcmp(msgCheck, message, sizeof(message)) != 0) {
	    //printf("WARNING: Original ciphertext not retrieved in UEA2"); // TODO: Not realistic
	//}
    })
    BENCH("uea2uia2", iterations, {
        init(message, sizeof(message), key, sizeof(key));
    }, {
        // Sender
	f8(key, count, bearer, 1, message, sizeof(message));
	uint8_t integrityIv[4];
	u8 *hashOut = f9(key, count, (u32)integrityIv, 1, message, sizeof(message));
	// Receiver
	u8 *hashCmp = f9(key, count, (u32)integrityIv, 1, message, sizeof(message));
	if (sizeof(hashOut) != sizeof(hashCmp) || memcmp(hashOut, hashCmp, sizeof(hashOut)) != 0) {
            printf("ERROR: Integrity check failed in uia2uea2");
        } else {
            f8(key, count, bearer, 1, message, sizeof(message));
        }
    })
    BENCH("chachapoly", iterations, {
        init(message, sizeof(message), key, sizeof(key));
        randombytes_buf(additional_data, sizeof(additional_data));
    }, {
        unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
        unsigned char ciphertext[sizeof(message) + crypto_aead_xchacha20poly1305_ietf_ABYTES];
        unsigned long long ciphertext_len;
        
        randombytes_buf(nonce, sizeof nonce);

        crypto_aead_chacha20poly1305_encrypt(
          ciphertext, &ciphertext_len,
          message, sizeof(message),
          additional_data, sizeof(additional_data),
          NULL, nonce, key);

        unsigned char decrypted[sizeof(message)];
        unsigned long long decrypted_len;
        int result = crypto_aead_chacha20poly1305_decrypt(
          decrypted, &decrypted_len,
          NULL,
          ciphertext, ciphertext_len,
          additional_data, sizeof(additional_data),
          nonce, key);
          
        if (result != 0) {
            printf("ERROR: Integrity check failed in Chachapoly");
        }

    })
    BENCH("chacha", iterations, {
        init(message, sizeof(message), key, sizeof(key));
        memcpy(msgCheck, message, sizeof(message));
    }, {
        unsigned char ciphertext[sizeof(message)];
        unsigned char nonce[sizeof(message)];
        // Key if fail
        randombytes_buf(nonce, sizeof(nonce));
        crypto_stream_chacha20_xor(ciphertext, message, sizeof(message), nonce, key);
        
        crypto_stream_chacha20_xor(ciphertext, message, sizeof(message), nonce, key);
        
        //if (sizeof(msgCheck) != sizeof(message) || memcmp(msgCheck, message, sizeof(message)) != 0) {
	    //printf("WARNING: Original ciphertext not retrieved in XOR");
        //}
    })
    BENCH("poly", iterations, {
        init(message, sizeof(message), polyKey, sizeof(polyKey));
    }, {
        unsigned char out[crypto_onetimeauth_BYTES];
        unsigned char cmp[crypto_onetimeauth_BYTES];
        crypto_onetimeauth(out, message, sizeof(message), polyKey);
        crypto_onetimeauth(cmp, message, sizeof(message), polyKey);
        if (crypto_onetimeauth_verify(out, message, sizeof(message), polyKey) != 0) {
            printf("ERROR: Integrity check failed in poly\n");
        }
    })
    BENCH("hmac", iterations, {
        init(message, sizeof(message), key, sizeof(key));
    }, {
        // Uses Sha-2
        unsigned char hashOut[crypto_auth_hmacsha512_BYTES];
        unsigned char hashCmp[crypto_auth_hmacsha512_BYTES];
        crypto_auth_hmacsha512(hashOut, message, sizeof(message), key);
        
        crypto_auth_hmacsha512(hashCmp, message, sizeof(message), key);
        
        if (sizeof(hashOut) != sizeof(hashCmp) || memcmp(hashOut, hashCmp, sizeof(hashOut)) != 0) {
            printf("ERROR: Integrity check failed in uia2");
        }
    })
    BENCH("aes", iterations, {
        init(message, sizeof(message), key, sizeof(key));
    }, {
        unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
	unsigned char ciphertext[sizeof(message) + crypto_aead_aes256gcm_ABYTES];
	unsigned long long ciphertext_len;

	randombytes_buf(nonce, sizeof nonce);

	crypto_aead_aes256gcm_encrypt(ciphertext, &ciphertext_len,
	    message, sizeof(message),
	    additional_data, sizeof(additional_data),
	    NULL, nonce, key);

	unsigned char decrypted[sizeof(message)];
	unsigned long long decrypted_len;
	if(ciphertext_len < crypto_aead_aes256gcm_ABYTES || crypto_aead_aes256gcm_decrypt(
	    decrypted, &decrypted_len,
	    NULL,
	    ciphertext, ciphertext_len,
	    additional_data, sizeof(additional_data),
	    nonce, key) != 0) {
			printf("Message forged!");
		}
    })
    BENCH("xor", iterations, {
        init(message, sizeof(message), key, sizeof(key));
        memcpy(msgCheck, message, sizeof(message));
    }, {
      // Sender
      for (size_t i = 0; i < sizeof(key); i++) {
          message[i] ^= key[i];  // Perform XOR on each byte
      }
      // Receiver
      for (size_t i = 0; i < sizeof(key); i++) {
          message[i] ^= key[i];  // Perform XOR on each byte
      }
      if (sizeof(msgCheck) != sizeof(message) || memcmp(msgCheck, message, sizeof(message)) != 0) {
	    printf("WARNING: Original ciphertext not retrieved in XOR");
      }
    })
    BENCH("chachasip", iterations, {
        init(message, sizeof(message), key, sizeof(key));
        memcpy(msgCheck, message, sizeof(message));
    }, {
        unsigned char ciphertext[sizeof(message)];
        unsigned char nonce[sizeof(message)];
        // Key if fail
        randombytes_buf(nonce, sizeof(nonce));
        crypto_stream_chacha20_xor(ciphertext, message, sizeof(message), nonce, key);
        
        sip(ciphertext, sizeof(ciphertext), key);
        // memcpy(cipherHash, ciphertext ); TODO, to simulate what actually happens
        
        crypto_stream_chacha20_xor(ciphertext, message, sizeof(message), nonce, key);
        
        if (sizeof(msgCheck) != sizeof(message) || memcmp(msgCheck, message, sizeof(message)) != 0) {
	    printf("WARNING: Original ciphertext not retrieved in XOR");
        }
      })
    return 0;
}
