#include <stdint.h>

void i2osp(void* dest, const void* src, uint32_t len);
void print_hex(const unsigned char* bytes, uint32_t len);
void unhexlify(const unsigned char* hex, uint32_t len, unsigned char* dest);