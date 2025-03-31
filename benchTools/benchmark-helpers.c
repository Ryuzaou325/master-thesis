#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <x86intrin.h>
#include <ctype.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>


 // siphash
#include "libs/SipHash/SipHash/halfsiphash.h"
#include "libs/SipHash/SipHash/siphash.h"

// 5G standard encryption/authentication
#include "libs/snow3g/snow3g/SNOW_3G.h"
#include "libs/snow3g/snow3g/f8.h"
#include "libs/snow3g/snow3g/f9.h"

// Ascon 
#include "libs/ascon/ascon/tests/crypto_aead.h"

// Libsodium: chacha, poly, aes, hmac
#include <sodium.h>

// Perf
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>

#define PERF_EVENT_ATTR_SIZE sizeof(struct perf_event_attr)

#define RDTSC
// #define RAM
// #define PERF

#define KEY_LENGTH 16 // 64 bits
#define IV_LENGTH 16
#define MAC_LENGTH 8

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
    char fileName[256];
    snprintf(fileName, sizeof(fileName), "/proc/%d/status", getpid());
    FILE *fp = fopen(fileName, "r"); // After this point, file will not be changed
    printf("Checking pid: %d\n", getpid());
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

int runRDTSC(char *funcName, int mlen) {
  #define MESSAGE_LENGTH mlen
  uint8_t message[MESSAGE_LENGTH];
  uint8_t key[KEY_LENGTH];

  randombytes_buf(message, sizeof(message));
  //printHex(message, sizeof(message));
  randombytes_buf(key, sizeof(key));
  #if defined (RDTSC)  
    unsigned long long start;
    unsigned long long end;
  #endif
  if (strcmp(funcName, "siphash") == 0) {
    uint8_t hashOutSender[8];
    uint8_t hashOutReceiver[8];
    #if defined RDTSC
      start = __rdtsc();
    #endif
    #if defined PERF
      int ctr = create_perf_event();
      start_counter(ctr);
    #endif
    // sender
    
    siphash(message, sizeof(message), key, hashOutSender, sizeof(hashOutSender));
    // receiver
    siphash(message, sizeof(message), key, hashOutReceiver, sizeof(hashOutReceiver));

    if (sizeof(hashOutReceiver) != sizeof(hashOutSender) 
        || memcmp(hashOutReceiver, hashOutSender, sizeof(hashOutReceiver)) != 0){
      printf("Failure: Hashes don't match!\n");
      return 0;
    }
    #if defined RDTSC
      end = __rdtsc();
      printf("%lld\n", end - start);
      return end - start;
    #endif
    #if defined PERF
      unsigned long long val = stop_counter(ctr);
      printf("running PERF: %d\n", val);
      return val;
    #endif
    #if defined RAM
      int val  = runRamCheck();
      printf("running RAM: %d\n", val);
      return val;
    #endif
    //printf("%lld\n", end - start);
  }/*
  else if (strcmp(funcName, "halfsiphash") == 0) {
    uint8_t hashOutSender[8];
    uint8_t hashOutReceiver[8];
    start = __rdtsc();
    // sender
    halfsiphash(message, sizeof(message), key, hashOutSender, sizeof(hashOutSender));
    // receiver
    halfsiphash(message, sizeof(message), key, hashOutReceiver, sizeof(hashOutReceiver));
    if (strcmp(hashOutSender, hashOutReceiver) == 0){
      printf("Failure: Hashes don't match!\n");
      return 0;
    }
    end = __rdtsc();
    return end - start;
  } 
  else if (strcmp(funcName, "ascon") == 0) {
    uint8_t nonce[IV_LENGTH];
    randombytes_buf(nonce, sizeof(nonce));
    uint8_t ADD_LEN = 0;
    uint8_t ciphertext[MESSAGE_LENGTH + MAC_LENGTH];
    uint8_t decrypted[MESSAGE_LENGTH];
    unsigned long long clen;
    unsigned long long decrypted_len;
    start = __rdtsc();
    crypto_aead_encrypt(ciphertext, &clen, message, sizeof(message), NULL, ADD_LEN, NULL, nonce, key);
    int result = crypto_aead_decrypt(decrypted, &decrypted_len, NULL, ciphertext, clen, NULL, ADD_LEN, nonce, key);
    if (result != 0) {
      printf("Failure: Hashes don't match!\n");
      return 0;
    }
    end = __rdtsc();
    return end - start;
  }
  else if (strcmp(funcName, "uia2") == 0) {
    
    uint8_t integrityIv[4];
    randombytes_buf(integrityIv, sizeof(integrityIv));
    u32 count = 0x389B7B12;
    start = __rdtsc();
    // TODO: warning for integrityIv, change it later
    u8 *macSender = f9(key, count, (u32)integrityIv, 1, message, sizeof(message));
    u8 *macReceiver = f9(key, count, (u32)integrityIv, 1, message, sizeof(message));
    // We don't know what argument 3 is??
    if (strcmp(macSender, macReceiver) != 0) {
      printf("Failure: Hashes don't match!");
      return 0;
    }
    end = __rdtsc();
    return end - start;
  }
  else if (strcmp(funcName, "uea2") == 0) {
    u32 bearer = 0x15;
    u32 count = 0x389B7B12;
    start = __rdtsc();
    f8(key, count, 0x15, 1, message, sizeof(message));
    f8(key, count, 0x15, 1, message, sizeof(message));
    end = __rdtsc();
    if (0) { // TODO: Compare 
      printf("Failure: Hashes don't match!");
      return 0;
    }
    return end - start;
  }
  else if (strcmp(funcName, "uea2uia2") == 0) {
    uint8_t integrityIv[4];
    randombytes_buf(integrityIv, sizeof(integrityIv));
    u32 bearer = 0x15;
    u32 count = 0x389B7B12;
    start = __rdtsc();
    f8(key, count, 0x15, 1, message, sizeof(message)); // encryption
    u8 *macSender = f9(key, count, (u32)integrityIv, 1, message, sizeof(message)); // add MAC
    u8 *macReceiver = f9(key, count, (u32)integrityIv, 1, message, sizeof(message)); // check MAC
    if (strcmp(macSender, macReceiver) != 0) {
      printf("Failure: Hashes don't match!");
      return 0;
    }
    f8(key, count, 0x15, 1, message, sizeof(message)); // decrypt
    end = __rdtsc();
    return end - start;
  }
  else if (strcmp(funcName, "chachapoly") == 0) {
    unsigned char keyChacha[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char ciphertext[MESSAGE_LENGTH + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned long long ciphertext_len;
    unsigned char decrypted[MESSAGE_LENGTH];
    unsigned long long decrypted_len;
    #define ADDITIONAL_DATA_LENGTH 4
    unsigned char additionalData[ADDITIONAL_DATA_LENGTH];
    
    crypto_aead_chacha20poly1305_keygen(keyChacha);
    randombytes_buf(nonce, sizeof nonce);
    randombytes_buf(additionalData, sizeof(additionalData));
    
    // printHex(message, sizeof(message));
    
    start = __rdtsc();
    crypto_aead_chacha20poly1305_encrypt(
      ciphertext, &ciphertext_len,
      message, MESSAGE_LENGTH,
      additionalData, ADDITIONAL_DATA_LENGTH,
      NULL, nonce, keyChacha);
    
    // printHex(ciphertext, sizeof(ciphertext));
    
    if (crypto_aead_chacha20poly1305_decrypt(
          decrypted, &decrypted_len,
          NULL,
          ciphertext, ciphertext_len,
          additionalData,
          ADDITIONAL_DATA_LENGTH,
          nonce, keyChacha) 
    != 0) {
      printf("Failure: Hashes don't match!");
      return 0;
    }
    // printHex(decrypted, sizeof(decrypted));
    end = __rdtsc();
    return end - start;
  }
  else if (strcmp(funcName, "chacha") == 0) {
    // TODO: To be implemented (copy code from libsodium lmao)
    // Initialization
    start = __rdtsc();
    // Encryption / MAC / AEAD
    if (0) {
      printf("Failure: Hashes don't match!");
      return 0;
    }
    end = __rdtsc();
    return end - start;
  }
  else if (strcmp(funcName, "poly") == 0) {
    // Initialization
    start = __rdtsc();
    // Encryption / MAC / AEAD
    if (0) {
      printf("Failure: Hashes don't match!");
      return 0;
    }
    end = __rdtsc();
    return end - start;
  }*/
  
  else if (strcmp(funcName, "aes") == 0) {
    // Initialization
    #if defined RDTSC
      start = __rdtsc();
    #endif
    // Encryption / MAC / AEAD
    if (0) {
      printf("Failure: Hashes don't match!");
      return 0;
    }
    #if defined RDTSC
      end = __rdtsc();
      return end - start;
    #endif
    #if defined RAM
      int val = runRamCheck();
      printf("%d\n", val);
      return val;
    #endif
  }/*
  else if (strcmp(funcName, "xor") == 0) {
    // Initialization
    start = __rdtsc();
    // Encryption / MAC / AEAD
    if (0) {
      printf("Failure: Hashes don't match!");
      return 0;
    }
    end = __rdtsc();
    return end - start;
  }*/
  else {
    printf("Internal error");
	        return 0;
  }
}

