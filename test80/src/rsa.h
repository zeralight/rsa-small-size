#ifndef __RSA__
#define __RSA__

#define RSA_KEYSIZE 256

#include <stdint.h>

unsigned char* rsa_encrypt(const unsigned char* from,
                            uint32_t flen,
                            const unsigned char* n,
                            uint32_t nlen,
                            uint32_t e);

#endif