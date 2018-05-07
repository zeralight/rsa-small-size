
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "sha1.h"
#include "rsa.h"
#include "util.h"

static unsigned char* get_rand(uint32_t count)
{
    unsigned char* res = malloc(count);
    memset(res, 1, count);
    return res;
}

static void strxor(const unsigned char* s1,
                    const unsigned char* s2,
                    unsigned char* dest,
                    uint32_t len)
{
    for (uint32_t i = 0; i < len; ++i)
        dest[i] = s1[i] ^ s2[i];
}

unsigned char* pkcs_rsa_encrypt(const unsigned char* message,
                                uint32_t mLen,
                                const unsigned char* n,
                                uint32_t nLen,
                                uint32_t e)
{
    // step 3a, 3b, 3c
    return rsa_encrypt(message, mLen, n, nLen, e);
}

unsigned char* mgf(unsigned char* mgfSeed, uint32_t mlen, uint32_t maskLen)
{
    printf("MGF1:\n");
    printf("mgfSeed = "); print_hex(mgfSeed, mlen);
    printf("maskLen = %d\n", maskLen);
    uint32_t len = (maskLen + SHA1_HASH_LEN - 1) / SHA1_HASH_LEN;
    unsigned char* T = malloc(len * SHA1_HASH_LEN);
    unsigned char* C = malloc(mlen + 4);
    unsigned char* hash_temp = malloc(SHA1_HASH_LEN);
    uint32_t i = 0;
    printf("iterations = %d\n", (maskLen + SHA1_HASH_LEN - 1) / SHA1_HASH_LEN);
    for (; i < (maskLen + SHA1_HASH_LEN - 1) / SHA1_HASH_LEN; ++i)
    {
        uint8_t temp[4];
        temp[0] = (uint8_t) ((i >> 24) & 255);
        temp[1] = (uint8_t) ((i >> 16) & 255);
        temp[2] = (uint8_t) ((i >> 8) & 255);
        temp[3] = (uint8_t) (i & 255);
        memcpy(C, mgfSeed, mlen);
        memcpy(C+mlen, temp, 4);
        printf("mgfSeed + C = "); print_hex(C, mlen + 4);
        sha1(C, mlen + 4, hash_temp);
        printf("hash = "); print_hex(hash_temp, 20);
        memcpy(T + i*SHA1_HASH_LEN, hash_temp, SHA1_HASH_LEN);
    }

    assert (i*SHA1_HASH_LEN >= maskLen);
    printf("T = "); print_hex(T, i*SHA1_HASH_LEN);

    unsigned char* ret = T;
    if (i*SHA1_HASH_LEN > maskLen)
    {
        ret = malloc(maskLen);
        memcpy(ret, T, maskLen);
        free(T);
    }
    printf("reutrning T = "); print_hex(ret, maskLen);

    free(C);
    free(hash_temp);

    return ret;
}

unsigned char* pkcs_rsa_oaep(const unsigned char* message,
                            uint32_t mLen,
                            const unsigned char* n,
                            uint32_t nlen,
                            uint32_t e)
{
    // TODO check if key is RSA

    const uint32_t k = 256;
    const uint32_t hLen = SHA1_HASH_LEN;

    // STEP 1b
    int32_t ps_len = k - mLen - 2*hLen - 2;
    if (ps_len < 0) {
        printf("Data too long.\n");
        return NULL;
    }

    // STEP 2a
    unsigned char* lHash = sha1_with_malloc((const unsigned char*)"", 0);
    printf("lHash = "); print_hex(lHash, SHA1_HASH_LEN); 
    // STEP 2b
    unsigned char* ps = calloc(ps_len, 1);
    printf("ps = "); print_hex(ps, ps_len);

    // STEP 2c
    uint32_t dbLen = SHA1_HASH_LEN + ps_len + 1 + mLen;
    unsigned char* db = malloc(dbLen);
    memcpy(db, lHash, SHA1_HASH_LEN);
    memcpy(db + SHA1_HASH_LEN, ps, ps_len);
    *(db + SHA1_HASH_LEN + ps_len) = 0x01;
    printf("message = "); print_hex(message, mLen);
    memcpy(db + SHA1_HASH_LEN + ps_len + 1, message, mLen);
    printf("db = "); print_hex(db, SHA1_HASH_LEN + ps_len + 1 + mLen);

    // STEP 2d
    unsigned char* ros = get_rand(hLen);
    printf("ros = "); print_hex(ros, hLen);

    // STEP 2e
    unsigned char* dbMask = mgf(ros, hLen, k - hLen - 1);
    printf("dbMask = "); print_hex(dbMask, k-hLen-1);

    // STEP 2f
    unsigned char* maskedDb = malloc(dbLen);
    strxor(db, dbMask, maskedDb, dbLen);
    printf("maskedDb = "); print_hex(maskedDb, dbLen);
    
    // Step 2g
    unsigned char* seedMask = mgf(maskedDb, dbLen, hLen);
    printf("seedMask = "); print_hex(seedMask, hLen);

    // Step 2h
    unsigned char* maskedSeed = malloc(hLen);
    strxor(ros, seedMask, maskedSeed, hLen);
    printf("maskedSeed = "); print_hex(maskedSeed, hLen);

    // Step 2i
    unsigned char* em = malloc(1 + hLen + dbLen);
    *em = 0x00;
    memcpy(em+1, maskedSeed, hLen);
    memcpy(em+1+hLen, maskedDb, dbLen);

    // Step 3a, 3b, 3c
    printf("em = ");
    print_hex(em, 1 + hLen + dbLen); printf("\n");

    unsigned char* m = pkcs_rsa_encrypt(em, 1 + hLen + dbLen, n, nlen, e);

    free(lHash);
    free(ps);
    free(db);
    free(ros);
    free(dbMask);
    free(maskedDb);
    free(seedMask);
    free(maskedSeed);
    free(em);

    return m;

}


int main()
{
    unsigned char n[] = "f4f8fac0c1822f90c1ff35b817efa46256b70d77e12982653a375986e4512643de269599b2d10b660287bea5a73e768ae488a0d7d38abefecca5f65968be6acaa24453db4614bf7a185bbfd5730b5770944949288677701028ad644c234fff852b0c453651947be3a35a34a07d2736f83c9f126f50d77020cfc37f917995da89a9f561340661fcaf1a3324ac03adf960e242e648dfb9b7ca8bc7cdd18c75a00c202123a9032990859deee8de17457d5f71eb435b18276f82f7d65d6af966b9f33f93fd0714b8b311904daba68866b592762a47c6b7f6dc909a3123149b01b1c721fffa907b877784621ac8ec0aa3fe4f185636890a0fd327d8fde0a389adb4b1";
    unsigned char d[] = "40286523ce8a5602c78c1b79976b3fd63177c7a339e9312969d1cd34b2df3df2506032960a6b0d5d2e14772dd35b5c988bb9ecc619b520c882b884886e1250cdb929c3fc8da22973c4a562dc7840e429abec75a8936efc7e7ee8ca77d657c148133a27764e6f60f30179428735bfeb79a006d941261f0652d19715f5f7adf389cf36e879c2990e1da0ee67f218abbd5f42c82bbb696869dbc5a504465702c1c5d8b637930cebc80021ec25e048f59ee80aab5cb515a60d10ef01329b4cd543ed195b7e4af0d8f75e826b878f76392ce9afe4f935957536451f3dc4637235d831a669d986672ffd4c636d8d1cefedd72a3fdd20b084063e12a980a9068ff67b71";
    uint32_t e = 0x10001;

    unsigned char input[] = "I wonder if it will work";
    
    
    unsigned char n_bytes[RSA_KEYSIZE];
    unhexlify(n, sizeof n - 1, n_bytes);

    unsigned char* cipher = pkcs_rsa_oaep(input, sizeof input - 1, n_bytes, RSA_KEYSIZE, e);

    unsigned char correct_encoding_hex[] = "00a7ecd4d781e4b4cefaead2cf4284408d2a1a0923872a8b71ccd860f9f9862a1a22b338c520bc5efd521d09c4e9163f4e18aba5c1d20debc65b65b6f80a86e26c104df019168a1bd3eee2c1229b0b9682bc646ef9b8dd81e42b68070cd86155ad0ecc6512e5c77b8417c7a239478a3ac9cbefa8c391dc9382ab97a30b9ac37a6065f0e493f76f7d424eaba3dbf45b3b827c49a02a25f90127ff4ee5604264af537e6dcdb1974adda02831411d068a27d1b047403ea6ba0547156bb943e5a8f1e1f1ed2cd0d637e6bb0306bbfa6a185b7a20039ae9cb16e470394373b6c4fa7fe417b52cf478a2c18831764ee106cc3688435d0c1ba3262902ec4911a2974d7a";
    unsigned char correct_encoding[256];
    unhexlify(correct_encoding_hex, 512, correct_encoding);

    printf("cipher: ");
    print_hex(cipher, RSA_KEYSIZE); printf("\n");

    free(cipher);
    return 0;
}