#define _GNU_SOURCE

// Includes for code
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <x86intrin.h>
#include <string.h>
#include <ctype.h>
#include <x86intrin.h>
#include <stdint.h>
#include <unistd.h>
#include <sched.h>

// fork stuff
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>

 // siphash
#include "libs/SipHash/SipHash/halfsiphash.h"
#include "libs/SipHash/SipHash/siphash.h"

// 5G standard encryption/authentication
#include "libs/snow3g/snow3g/SNOW_3G.h"
#include "libs/snow3g/snow3g/f8.h"
#include "libs/snow3g/snow3g/f9.h"

// Ascon 
#include "libs/ascon/ascon/tests/crypto_aead.h"

// Perf
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

// cflush
#include <emmintrin.h>



#define CACHE_LINE_SIZE 64   // Most CPUs use 64-byte cache lines
#define CACHE_SIZE (8 * 1024 * 1024)  // Assume 8MB L3 cache

#define PERF_EVENT_ATTR_SIZE sizeof(struct perf_event_attr)
#define FLUSH_CACHES 1


#define BENCH(name, iterations, bench) if (strcmp(argv[1], name) == 0) { \
        printf("\nRunning a benchmark for %s with %d iterations\n", name, iterations); \
	unsigned long sum = 0; \
	unsigned long max = 0; \
		if (FLUSH_CACHES) flush_all_caches(); \
		bench; \
	        int ram = runRamCheck(); \
	        sum += ram; \
	        if (max < ram) max = ram; \
	printf("\nAverage RAM Usage: %f Kilobytes\n", ((double)sum / iterations)); \
	printf("Maximum RAM Usage: %ld Kilobytes\n", max); \
	sum = 0; \
	max = 0; \
	        if (FLUSH_CACHES) flush_all_caches(); \
		unsigned long long start = __rdtsc(); \
	        bench; \
	        unsigned long long end = __rdtsc(); \
	        sum += (end - start); \
	        if (max < (end - start)) max = (end - start); \
	printf("\nRDTSC Average Cycle count: %f\n", ((double)sum / iterations)); \
	printf("RDTSC Maximum Cycle count: %ld\n", max); \
	sum = 0; \
	max = 0; \
	int ctr = create_perf_event(); \
		if (FLUSH_CACHES) flush_all_caches(); \
	        start_counter(ctr); \
	        bench; \
	        long long result = stop_counter(ctr); \
	        sum += result; \
	        if (max < result) max = result; \
	printf("\nPerf Average Instruction count: %f\n", ((double)sum / iterations)); \
	printf("Perf Maximum Instruction count: %ld\n", max); \
}


void pin_to_core(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    
    int result = sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
    if (result != 0) {
        perror("sched_setaffinity");
    }
}

void createRandomSequence(uint8_t *sequence, unsigned int length) {
	for (int i = 0; i < length; i++) {
		sequence[i] = rand() % 256;
	}
}

void printHex(unsigned char *sequence) {
        for (int i = 0; i < sizeof(sequence); i++) {
                printf("%02x", sequence[i]);
        }
        printf("\n");
}

 // Flush all cache
void flush_all_caches() {
    char *buffer = (char *)malloc(CACHE_SIZE);
    if (!buffer) {
        perror("Memory allocation failed");
        return;
    }

    for (size_t i = 0; i < CACHE_SIZE; i += CACHE_LINE_SIZE) {
        _mm_clflush(&buffer[i]);  // Flush each cache line
    }
    _mm_sfence();  // Ensure all flushes complete

    free(buffer);
}

// Function to create and configure a perf_event
int create_perf_event() {
    struct perf_event_attr attr;
    memset(&attr, 0, PERF_EVENT_ATTR_SIZE);

    // Set the event type to count instructions
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_INSTRUCTIONS;
    
    // Set the event for the current CPU
    attr.size = PERF_EVENT_ATTR_SIZE;
    attr.disabled = 1;  // We disable the event initially

    // Open the event (this uses the /dev/perf_event interface)
    int fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
    
    if (fd == -1) {
        perror("perf_event_open");
        return -1;
    }

    return fd;
}

// Function to start counting
void start_counter(int fd) {
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);   // Reset the counter
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);  // Enable the event
}

// Function to read the counter value
long long read_counter(int fd) {
    long long count;
    if (read(fd, &count, sizeof(count)) == -1) {
        perror("read");
        return -1;
    }
    return count;
}

// Function to stop counting and get the result
long long stop_counter(int fd) {
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); // Disable the event
    return read_counter(fd);
}

int extract_integer(const char *str) {
    // Skip over non-numeric characters

    while (*str != '\0' && !isdigit(*str) && *str != '-' && *str != '+') {
        str++;
    }
    
    // Now we expect to find the integer
    if (*str == '\0') {
        printf("No integer found in the string.\n");
        return 0;  // No integer found
    }

    // Convert the string to an integer
    char *endptr;
    long int num = strtol(str, &endptr, 10);
    
    // Return the converted integer
    return (int)num;
}

int runRamCheck() {
    FILE *fp = fopen("/proc/self/status", "r"); // After this point, file will not be changed
    if (fp == NULL) {
        perror("fopen");
        //printf("failed to open file");
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
		//printf(line);
        if (strncmp(line, "VmHWM", 5) == 0) {  // VmHWM is the peak memory usage
			fclose(fp);
            return extract_integer(line);
        }
    }
    printf("Error, did not find file");
    return 0;
}

#define MESSAGE_LENGTH 4
#define KEY_LENGTH 8
#define IV_LENGTH 8
#define MAC_LENGTH 16

int main(int argc, char *argv[]) {
	pin_to_core(0);

	if (argc < 3) {
		printf("Usage: ./benchmark <algorithm name> <iterations>\n");
		return 1;
	}
	
	if (argv[2] != NULL && *argv[2] != '\0' && argv[2][0] != '0') {
	        int i = 0;
	        for (i = 0; argv[2][i] != '\0'; i++) {
	                if (!isdigit((unsigned char)argv[2][0])) {
	                        printf("Invalid iteration input. Must be a positive value not leading with 0 and less than 9999999\n");
	                        return 1;
	                }
	        }
	        if (i > 7) {
	                printf("Invalid iteration input. Must be a positive value not leading with 0 and less than 9999999\n");
	                return 1;
	        }
	}
	else {
	        printf("Invalid iteration input. Must be a positive value not leading with 0 and less than 9999999\n");
	        return 1;
	}
        
	if (strcmp(argv[1], "siphash") != 0 && strcmp(argv[1], "halfsiphash") != 0 &&
	    strcmp(argv[1], "ascon") != 0 && strcmp(argv[1], "uia2") != 0 &&
	    strcmp(argv[1], "uea2") != 0 && strcmp(argv[1], "uia2uea2") != 0 &&
	    strcmp(argv[1], "chachapoly") != 0 && strcmp(argv[1], "chacha") != 0 &&
	    strcmp(argv[1], "poly") != 0 &&
	    strcmp(argv[1], "hmac") != 0 && strcmp(argv[1], "aes") != 0 &&
	    strcmp(argv[1], "xor") != 0) {
	        printf("Incorrect algorithm name choice. Options: \nsiphash, halfsiphash, ascon, uia2, uea2, uia2uea2, chachapoly, chacha, poly,  hmac, aes, xor \n");
	        return 1;
	}
	
	srand(time(NULL));  // We initialize it here, only once. Calling it more ofrten makes randomization more predicatable
	
	//Initializing values. These lengths should be in bytes. Edit as needed;

	uint8_t message[MESSAGE_LENGTH];
	uint8_t key[KEY_LENGTH];

	createRandomSequence(message, sizeof(message));
	createRandomSequence(key, sizeof(key));
	
	printf("Plaintext message: "); printHex(message);
	printf("key: "); printHex(key);
	
	int iterations = atoi(argv[2]);
	

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


	for (int i = 0; i < iterations; i++) {
		pids[i] = fork();
        if (pids[i] == 0) { // Child process
			close(pipefd[i][0]); // close read end
			// Can BENCH return values? I.e. ram usage, cycles
            BENCH("siphash", iterations, {
				uint8_t hashOut[8];
				siphash(message, sizeof(message), key, hashOut, sizeof(hashOut));
			});

			BENCH("halfsiphash", iterations, {
				uint8_t hashOut[4];
				halfsiphash(message, sizeof(message), key, hashOut, sizeof(hashOut));
			})

			BENCH("ascon", iterations, {
				uint8_t nonce[16];
				createRandomSequence(nonce, sizeof(nonce));
				uint8_t ADD_LEN = 0;
				uint8_t ciphertext[MESSAGE_LENGTH + MAC_LENGTH];
				uint8_t decrypted[MESSAGE_LENGTH];
				unsigned long long clen;
				crypto_aead_encrypt(ciphertext, &clen, message, sizeof(message), NULL, ADD_LEN, NULL, nonce, key);
				unsigned long long decrypted_len;
				int result = crypto_aead_decrypt(decrypted, &decrypted_len, NULL, ciphertext, clen, NULL, ADD_LEN, nonce, key);
			})
			// change &value for actual returned values from bench
			int value = 1;
			write(pipefd[i][1], &value, sizeof(value));
			close(pipefd[i][1]); // close write end

            exit(EXIT_SUCCESS);
        } else if (pids[i] < 0) {
            perror("fork failed");
            exit(1);
        }
	}
	int count = 0;
	// parent process collects values
	for (int i = 0; i < iterations; i++) {
		int received_value;
		close(pipefd[i][1]); // close write end on parent
		// read and store value in received_value
		read(pipefd[i][0], &received_value, sizeof(received_value));
		count += received_value;
		close(pipefd[i][0]); // close read end
		printf("Received value = %d\n", received_value);

		waitpid(pids[i], NULL, 0); // wait for child to finish
	}
	printf("%d\n", count);



	/*
	BENCH("siphash", iterations, {
		uint8_t hashOut[8];
		siphash(message, sizeof(message), key, hashOut, sizeof(hashOut));
	})*/

	/*
	BENCH("halfsiphash", iterations, {
	        uint8_t hashOut[4];
	        halfsiphash(message, sizeof(message), key, hashOut, sizeof(hashOut));
	})
	*/
	/*
	BENCH("ascon", iterations, {
	        uint8_t nonce[16];
	        createRandomSequence(nonce, sizeof(nonce));
	        uint8_t ADD_LEN = 0;
	        uint8_t ciphertext[MESSAGE_LENGTH + MAC_LENGTH];
	        uint8_t decrypted[MESSAGE_LENGTH];
	        unsigned long long clen;
	        crypto_aead_encrypt(ciphertext, &clen, message, sizeof(message), NULL, ADD_LEN, NULL, nonce, key);
	        unsigned long long decrypted_len;
	        int result = crypto_aead_decrypt(decrypted, &decrypted_len, NULL, ciphertext, clen, NULL, ADD_LEN, nonce, key);
	})
	*/
	BENCH("uia2", iterations, {
	        u32 bearer = 0x15;
	        u32 count = 0x389B7B12;
	        f8(key, count, 0x15, 1, message, sizeof(message));
	        // UIA2 encryption algorithm = UIA2 decryption algorithm
	})
	BENCH("uea2", iterations, {
	        uint8_t integrityIv[4];
	        createRandomSequence(integrityIv, sizeof(integrityIv));
	        u32 count = 0x389B7B12;
	        // warning for integrityIv, change it later
	        u8 *mac = f9(key, count, (u32)integrityIv, 1, message, sizeof(message));
	        // We don't know what argument 3 is??
	})
	BENCH("uia2uea2", iterations, {
	        u32 bearer = 0x15;
	        u32 count = 0x389B7B12;
	        f8(key, count, 0x15, 1, message, sizeof(message));
	        // warning for integrityIv, change it later
	        uint8_t integrityIv[4];
	        createRandomSequence(integrityIv, sizeof(integrityIv));
	        uint8_t integrityKey[8];
	        createRandomSequence(integrityKey, sizeof(integrityKey));
	        u8 *mac = f9(integrityKey, count, (u32)integrityIv, 1, message, sizeof(message));
	        // We don't know what argument 3 is??
	})
	BENCH("chachapoly", iterations, {
	
	})
	BENCH("chacha", iterations, {
	
	})
	BENCH("poly", iterations, {
	
	})
	BENCH("hmac", iterations, {
	
	})
	BENCH("aes", iterations, {
	
	})
	BENCH("xor", iterations, {
	
	})
	return 0;
}
