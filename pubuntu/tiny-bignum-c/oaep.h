#ifndef _OAEP_H
#define _OAEP_H

#include "sha1.h"

#define RSA_KEYSIZE 2048

#include <stdint.h>

uint8_t* pkcs_oaep_mgf1_encode(uint8_t* message, uint32_t mLen, uint32_t length);
uint8_t* pkcs_oaep_mgf1_decode(uint8_t* message, uint32_t mLen);

#endif /* _OAEP_H */