// Code for these algorithms are short so we just put them in a file
#include "../libs/SipHash/SipHash/halfsiphash.h"
#include "../libs/SipHash/SipHash/siphash.h"
#include <stdio.h>

void sip(uint8_t *message, unsigned int message_length, uint8_t *key) {
    
    uint8_t hashOut[8];
    siphash(message, message_length, key, hashOut, sizeof(hashOut));
    
    uint8_t hashCmp[8];
    siphash(message, message_length, key, hashCmp, sizeof(hashCmp));
    
    if(sizeof(hashOut) != sizeof(hashCmp) || memcmp(hashOut, hashCmp, sizeof(hashOut)) != 0) {
        printf("ERROR: Integrity check fail in Siphash");
    }
}

void halfsip(uint8_t *message, unsigned int message_length, uint8_t *key) {
    
    uint8_t hashOut[4];
    halfsiphash(message, message_length, key, hashOut, sizeof(hashOut));
    
    uint8_t hashCmp[4];
    halfsiphash(message, message_length, key, hashCmp, sizeof(hashCmp));
    
    if(sizeof(hashOut) != sizeof(hashCmp) || memcmp(hashOut, hashCmp, sizeof(hashOut)) != 0) {
        printf("ERROR: Integrity check fail in Halfsiphash");
    }
}
