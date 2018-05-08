#include "util.h"

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

void i2osp(void* dest, const void* src, uint32_t len)
{
    static int endianness = -1;
    if (endianness == -1)
    {
        uint16_t x = 0x0102;
        void* p = (void*)&x;
        endianness = (*(uint8_t*)p == 0x01);
    }

    if (endianness == 1)
    {
        memcpy(dest, src, len);
    }
    else
    {
        for (uint32_t i = 0; i < len; ++i)
            memcpy(((char*)dest)+i, ((char*)src)+len-i-1, 1);
    }
}


void print_hex(const unsigned char* bytes, uint32_t len)
{
    for (uint32_t i = 0; i < len; ++i)
        printf("%.2x", bytes[i]);
    printf("\n");
}

void unhexlify(const unsigned char* from, uint32_t len, unsigned char* to)
{
    assert (!(len & 1));
    for (uint32_t i = 0; i < len / 2; ++i)
    {
        uint8_t a = from[2*i];
        uint8_t b = from[2*i+1];
        a -= (a < 'a') ? '0' : 'a'-10;
        b -= (b < 'a') ? '0' : 'a'-10;
        to[i] = (a << 4) + b;
    }
}
