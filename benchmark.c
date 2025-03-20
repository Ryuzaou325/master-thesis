#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <x86intrin.h>
#include <string.h>
#include <ctype.h>
#include <x86intrin.h>
#include <stdint.h>

 
#include "libs/SipHash/SipHash/halfsiphash.h"
#include "libs/SipHash/SipHash/siphash.h"

#include "libs/snow3g/snow3g/SNOW_3G.h"
#include "libs/snow3g/snow3g/f8.h"
#include "libs/snow3g/snow3g/f9.h"

#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>    // For syscall()
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define PERF_EVENT_ATTR_SIZE sizeof(struct perf_event_attr)

#define BENCH(name, iterations, bench) if (strcmp(argv[1], name) == 0) { \
        printf("\nRunning a benchmark for %s with %d iterations\n", name, iterations); \
	unsigned long sum = 0; \
	unsigned long max = 0; \
	for (int i = 0; i < iterations; i++) { \
	        bench; \
	        int ram = runRamCheck(); \
	        sum += ram; \
	        if (max < ram) max = ram; \
	} \
	printf("\nAverage RAM Usage: %f Kilobytes\n", ((double)sum / iterations)); \
	printf("Maximum RAM Usage: %d Kilobytes\n", max); \
	sum = 0; \
	max = 0; \
	for (int i = 0; i < iterations; i++) { \
	        unsigned long long start = __rdtsc(); \
	        bench; \
	        unsigned long long end = __rdtsc(); \
	        sum += (end - start); \
	        if (max < (end - start)) max = (end - start); \
	} \
	printf("\nRDTSC Average Cycle count: %f\n", ((double)sum / iterations)); \
	printf("RDTSC Maximum Cycle count: %d\n", max); \
	sum = 0; \
	max = 0; \
	int ctr = create_perf_event(); \
	for (int i = 0; i < iterations; i++) { \
	        start_counter(ctr); \
	        bench; \
	        long long result = stop_counter(ctr); \
	        sum += result; \
	        if (max < result) max = result; \
	}\
	printf("\nPerf Average Instruction count: %f\n", ((double)sum / iterations)); \
	printf("Perf Maximum Instruction count: %d\n", max); \
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
        if (strncmp(line, "VmHWM", 5) == 0) {  // VmHWM is the peak memory usage
            return extract_integer(line);
        }
    }
    printf("Error, did not find file");
    return 0;
}

int main(int argc, char *argv[]) {

        srand(time(NULL));  // We initialize it here, only once. Calling it more ofrten makes randomization more predicatable
	
	//Initializing values. These lengths should be in bytes. Edit as needed;
	unsigned int MESSAGE_LENGTH = 4;
	unsigned int CONFIDENTIALITY_KEY_LENGTH = 8;
	unsigned int INTEGRITY_KEY_LENGTH = 8;
	unsigned int CONFIDENTIALITY_IV_LENGTH = 4;
	unsigned int INTEGRITY_IV_LENGTH = 4;
	unsigned int MAC_LENGTH = 0; // Ssometimes influences algorithm choice (siphash vs halfsiphash)

	uint8_t message[4];
	uint8_t confidentialityKey[8];
	uint8_t integrityKey[8];
	uint8_t confidentialityIv[4];
	uint8_t integrityIv[4];

	createRandomSequence(message, sizeof(message));
	createRandomSequence(confidentialityKey, sizeof(confidentialityKey));
        createRandomSequence(integrityKey, sizeof(integrityKey));
	createRandomSequence(confidentialityIv, sizeof(confidentialityIv));
	createRandomSequence(integrityIv, sizeof(integrityIv));
	
	printf("Plaintext message: "); printHex(message);
	printf("Confidentiality key: "); printHex(confidentialityKey);
	printf("Integrity key: "); printHex(integrityKey);
	printf("Confidentiality IV: "); printHex(confidentialityIv);
	printf("Integrity IV: "); printHex(integrityIv);

	if (argc < 3) {
		printf("Usage: ./benchmark <algorithm name> <iterations>\n");
		return 1;
	}
	
	if (argv[2] != NULL && *argv[2] != '\0' && argv[2][0] != '0') {
	        int i = 0;
	        for (i = 0; argv[2][i] != '\0'; i++) {
	                if (!isdigit((unsigned char)argv[2][0])) {
	                        printf("Invalid iteration input. Must be a positive value not leading with 0 and less than 99999\n");
	                        return 1;
	                }
	        }
	        if (i > 5) {
	                printf("Invalid iteration input. Must be a positive value not leading with 0 and less than 99999\n");
	                return 1;
	        }
	}
	else {
	        printf("Invalid iteration input. Must be a positive value not leading with 0 and less than 99999\n");
	        return 1;
	}
        
	if (strcmp(argv[1], "siphash") != 0 && strcmp(argv[1], "halfsiphash") != 0 &&
	    strcmp(argv[1], "ascon") != 0 && strcmp(argv[1], "uia2") != 0 &&
	    strcmp(argv[1], "uea2") != 0 && strcmp(argv[1], "uia2uea2") != 0 &&
	    strcmp(argv[1], "chachapoly") != 0 && strcmp(argv[1], "chacha") != 0 &&
	    strcmp(argv[1], "poly") != 0 && strcmp(argv[1], "threefish") != 0 &&
	    strcmp(argv[1], "hmac") != 0 && strcmp(argv[1], "aes") != 0 &&
	    strcmp(argv[1], "xor") != 0) {
	        printf("Incorrect algorithm name choice. Options: \nsiphash, halfsiphash, ascon, uia2, uea2, uia2uea2, chachapoly, chacha, poly, threefish, hmac, aes, xor \n");
	        return 1;
	}
	
	int iterations = atoi(argv[2]);
	
	BENCH("siphash", iterations, {
	        uint8_t hashOut[8];
	        siphash(message, sizeof(message), integrityKey, hashOut, sizeof(hashOut));
	})
	BENCH("halfsiphash", iterations, {
	        uint8_t hashOut[4];
	        halfsiphash(message, sizeof(message), integrityKey, hashOut, sizeof(hashOut));
	})
	BENCH("ascon", iterations, {
	        
	})
	BENCH("uia2", iterations, {
	        u32 bearer = 0x15;
	        u32 count = 0x389B7B12;
	        f8(confidentialityKey, count, 0x15, 1, message, sizeof(message));
	        // UIA2 encryption algorithm = UIA2 decryption algorithm
	})
	BENCH("uea2", iterations, {
	        u32 count = 0x389B7B12;
	        // warning for integrityIv, change it later
	        u8 *mac = f9(integrityKey, count, (u32)integrityIv, 1, message, sizeof(message));
	        // We don't know what argument 3 is??
	})
	BENCH("uia2uea2", iterations, {
	        u32 bearer = 0x15;
	        u32 count = 0x389B7B12;
	        f8(confidentialityKey, count, 0x15, 1, message, sizeof(message));
	        // warning for integrityIv, change it later
	        u8 *mac = f9(integrityKey, count, (u32)integrityIv, 1, message, sizeof(message));
	        // We don't know what argument 3 is??
	})
	BENCH("chachapoly", iterations, {
	
	})
	BENCH("chacha", iterations, {
	
	})
	BENCH("poly", iterations, {
	
	})
	BENCH("threefish", iterations, {
	
	})
	BENCH("hmac", iterations, {
	
	})
	BENCH("aes", iterations, {
	
	})
	BENCH("xor", iterations, {
	
	})
	return 0;
}
