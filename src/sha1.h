#include <stdint.h>
#define SHA1_HASH_LEN 20

#define htonl(n) (((((uint32_t)(n) & 0xFF)) << 24) | \
                  ((((uint32_t)(n) & 0xFF00)) << 8) | \
                  ((((uint32_t)(n) & 0xFF0000)) >> 8) | \
                  ((((uint32_t)(n) & 0xFF000000)) >> 24))

                  
int sha1(const unsigned char* input, uint32_t len, unsigned char* output);
int sha1_uint8_t(const uint8_t* input, uint32_t len, uint8_t* output);
uint8_t* sha1_with_malloc(const unsigned char* input, uint32_t len);
uint8_t* sha1_uint8_t_with_malloc(const uint8_t* input, uint32_t len);

void sha1_start();
void sha1_terminate();
