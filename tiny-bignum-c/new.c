
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "sha1.h"

unsigned char* get_rand(uint32_t count)
{
    unsigned char* res = malloc(count);
    return res;
}

static void strxor(const char* s1, const char* s2, char* dest, uint32_t len)
{
    for (uint32_t i = 0; i < len; ++i)
        dest[i] = s1[i] ^ s2[i];
}

unsigned char* encrypt(unsigned char* message, uint32_t mLen)
{
    // TODO check if key is RSA

    const uint32_t modBits = 2048;
    const uint32_t k = 256;
    const uint32_t hLen = SHA1_HASH_LEN;

    // STEP 1b
    int32_t ps_len = k - mLen - 2*hLen - 2;
    if (ps_len < 0) {
        printf("Data too long.\n");
        return NULL;
    }

    // STEP 2a
    unsigned char* lHash = sha1_with_malloc("", 0);

    // STEP 2b
    unsigned char* ps = calloc(ps_len, 1);

    // STEP 2c
    uint32_t dbLen = SHA1_HASH_LEN + ps_len + 1 + mLen;
    unsigned char* db = malloc(dbLen);
    memcpy(db, lHash, SHA1_HASH_LEN);
    memcpy(db + SHA1_HASH_LEN, ps, ps_len);
    *(db + SHA1_HASH_LEN + ps_len) = 0x00;
    memcpy(db + SHA1_HASH_LEN + ps_len + 1, message, mLen);

    // STEP 2d
    unsigned char* ros = get_rand(hLen);
    
    // STEP 2e
    unsigned char* dbMask = mgf(ros, k - hLen - 1);

    // STEP 2f
    unsigned char* maskedDb = malloc(dbLen);
    strxor(db, dbMask, dbLen, maskedDb);
    
    // Step 2g
    unsigned char* seedMask = mgf(maskedDb, hLen);

    // Step 2h
    unsigned char* maskedSeed = malloc(hLen);
    strxor(ros, seedMask, maskedSeed, hLen);

    // Step 2i
    unsigned char* em = malloc(256);
    *em = 0x00;
    memcpy(em+1, maskedSeed, )
}