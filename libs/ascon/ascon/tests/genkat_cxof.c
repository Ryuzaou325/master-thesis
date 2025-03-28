//
// NIST-developed software is provided by NIST as a public service.
// You may use, copy and distribute copies of the software in any medium,
// provided that you keep intact this entire notice. You may improve,
// modify and create derivative works of the software or any portion of
// the software, and you may copy and distribute such modifications or
// works. Modified works should carry a notice stating that you changed
// the software and should note the date and nature of any such change.
// Please explicitly acknowledge the National Institute of Standards and
// Technology as the source of the software.
//
// NIST-developed software is expressly provided "AS IS." NIST MAKES NO
// WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT OR ARISING BY OPERATION
// OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT AND DATA
// ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE
// SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE
// CORRECTED. NIST DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE
// USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE
// CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
//
// You are solely responsible for determining the appropriateness of using and
// distributing the software and you assume all risks associated with its use,
// including but not limited to the risks and costs of program errors,
// compliance with applicable laws, damage to or loss of data, programs or
// equipment, and the unavailability or interruption of operation. This software
// is not intended to be used in any situation where a failure could cause risk
// of injury or damage to property. The software developed by NIST employees is
// not subject to copyright protection within the United States.
//

// This software is modified to work for CXOF (28 Nov 2024)
//
// This file has been modified. The history of changes can be found at:
// https://github.com/ascon/ascon-c/commits/main/tests/genkat_cxof.c

// disable deprecation for sprintf and fopen
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "crypto_cxof.h"

#if defined(AVR_UART)
#include "avr_uart.h"
#endif

#define KAT_SUCCESS 0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR -3
#define KAT_CRYPTO_FAILURE -4

#define MAX_FILE_NAME 256
#ifndef MAX_MESSAGE_LENGTH
#define MAX_MESSAGE_LENGTH 32
#endif
#define MAX_CUSTOMIZATION_LENGTH 32

void init_buffer(unsigned char offset, unsigned char* buffer,
                 unsigned long long numbytes);

void fprint_bstr(FILE* fp, const char* label, const unsigned char* data,
                 unsigned long long length);

int generate_test_vectors();

int main() {
  int ret = generate_test_vectors();
  if (ret != KAT_SUCCESS) {
    fprintf(stderr, "test vector generation failed with code %d\n", ret);
  }
  exit(ret);
}

int generate_test_vectors() {
  FILE* fp;
#if !defined(AVR_UART)
  char fileName[MAX_FILE_NAME];
#endif
  unsigned char* msg;
  unsigned char* cs;
  unsigned char digest[CRYPTO_BYTES];
  unsigned long long mlen;
  unsigned long long cslen;
  int count = 1;
  int func_ret, ret_val = KAT_SUCCESS;

#if !defined(AVR_UART)
  sprintf(fileName, "LWC_CXOF_KAT_128_%d.txt", (CRYPTO_BYTES * 8));
  if ((fp = fopen(fileName, "w")) == NULL) {
    fprintf(stderr, "Couldn't open <%s> for write\n", fileName);
    return KAT_FILE_OPEN_ERROR;
  }
#else
  avr_uart_init();
  stdout = &avr_uart_output;
  stdin = &avr_uart_input_echo;
  fp = stdout;
#endif

  for (mlen = 0; mlen <= MAX_MESSAGE_LENGTH; mlen++) {
    msg = malloc(mlen);
    init_buffer(0x00, msg, mlen);

    for (cslen = 0; cslen <= MAX_CUSTOMIZATION_LENGTH; cslen++) {
      cs = malloc(cslen);
      init_buffer(0x10, cs, cslen);

      fprintf(fp, "Count = %d\n", count++);
      fprint_bstr(fp, "Msg = ", msg, mlen);
      fprint_bstr(fp, "Z = ", cs, cslen);

      if ((func_ret =
               crypto_cxof(digest, CRYPTO_BYTES, msg, mlen, cs, cslen)) != 0) {
        fprintf(fp, "crypto_hash returned <%d>\n", ret_val);
        ret_val = KAT_CRYPTO_FAILURE;
        free(cs);
        break;
      }

      fprint_bstr(fp, "MD = ", digest, CRYPTO_BYTES);
      fprintf(fp, "\n");
      free(cs);
    }
    free(msg);
    if (ret_val != KAT_SUCCESS) break;
  }

#if !defined(AVR_UART)
  fclose(fp);
#else
  fprintf(stderr, "Press Ctrl-C to quit\n");
#endif

  return ret_val;
}

void fprint_bstr(FILE* fp, const char* label, const unsigned char* data,
                 unsigned long long length) {
  unsigned long long i;
  fprintf(fp, "%s", label);
  for (i = 0; i < length; i++) fprintf(fp, "%02X", data[i]);
  fprintf(fp, "\n");
}

void init_buffer(unsigned char offset, unsigned char* buffer,
                 unsigned long long numbytes) {
  unsigned long long i;
  for (i = 0; i < numbytes; i++) buffer[i] = (unsigned char)(offset + i);
}
