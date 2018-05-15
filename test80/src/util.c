#include "util.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


void *heap_get(uint32_t n) {
	if (heap.brk + n > heap.buf + heap.size) return NULL;
  void *ret = heap.brk;
  heap.brk += n;

  return ret;
}

void heap_free(uint32_t n) {
  if (heap.buf + n >= heap.brk)
    heap.brk = heap.buf;
  else
    heap.brk -= n;
}


#if !defined(BIG_ENDIAN)
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
    uint32_t i;
    for (i = 0; i < len; ++i)
      memcpy(((char*)dest)+i, ((char*)src)+len-i-1, 1);
  }
}
#endif

#if defined(USE_IO) || !defined(__H8_2329F__)
void print_hex(const unsigned char* bytes, uint32_t len)
{
  uint32_t i;
  for (i = 0; i < len; ++i)
    printf("%.2x", bytes[i]);
  printf("\n");
}

#endif


#if defined(IMPLEMENT_ALL)
void unhexlify(const unsigned char* from, uint32_t len, unsigned char* to)
{
  require (!(len & 1), "invalid length: not even");
  uint32_t i;
  for (i = 0; i < len / 2; ++i)
  {
    uint8_t a = from[2*i];
    uint8_t b = from[2*i+1];
    a -= (a < 'a') ? '0' : 'a'-10;
    b -= (b < 'a') ? '0' : 'a'-10;
    to[i] = (a << 4) + b;
  }
}
#endif