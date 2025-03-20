/*---------------------------------------------------------
*
f8.h
*---------------------------------------------------------*/
#ifndef F8_H_
#define F8_H_
#include "SNOW_3G.h"
/* f8.
* Input key: 128 bit Confidentiality Key.
* Input count:32-bit Count, Frame dependent input.
* Input bearer: 5-bit Bearer identity (in the LSB side).
* Input dir:1 bit, direction of transmission.
* Input data: length number of bits, input bit stream.
* Input length: 32 bit Length, i.e., the number of bits to be encrypted or
*
decrypted.
* Output data: Output bit stream. Assumes data is suitably memory
* allocated.
* Encrypts/decrypts blocks of data between 1 and 2^32 bits in length as
* defined in Section 3.
*/
void f8( u8 *key, u32 count, u32 bearer, u32 dir, u8 *data, u32 length );
#endif