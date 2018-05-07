#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sha1.h"

static uint8_t block[64], extra_block[64];
uint32_t H[5] =
{
  0x67452301,
  0xEFCDAB89,
  0x98BADCFE,
  0x10325476,
  0xC3D2E1F0
};

static void sha1_init()
{
  static int srand_done = 0;
  if (!srand_done)
  {
    srand(time(NULL));
    srand_done = 1;
  }

  H[0] = 0x67452301;
  H[1] = 0xEFCDAB89;
  H[2] = 0x98BADCFE;
  H[3] = 0x10325476;
  H[4] = 0xC3D2E1F0;

}
uint32_t rotl( uint32_t x, int shift )
{
  return (x << shift) | (x >> (sizeof(x)*8 - shift));
}

uint32_t roundFunc( uint32_t b, uint32_t c, uint32_t d, int roundNum )
{
  if( roundNum <= 19 )
  {
    return (b & c) | ((~b) & d);
  }
  else if( roundNum <= 39 )
  {
    return ( b ^ c ^ d );
  }
  else if( roundNum <= 59 )
  {
    return (b & c) | (b & d) | (c & d);
  }
  else
  {
    return ( b ^ c ^ d );
  }
}

uint32_t kForRound( int roundNum )
{
  if( roundNum <= 19 )
  {
    return 0x5a827999;
  }
  else if( roundNum <= 39 )
  {
    return 0x6ed9eba1;
  }
  else if( roundNum <= 59 )
  {
    return 0x8f1bbcdc;
  }
  else
  {
    return 0xca62c1d6;
  }
}

int pad(uint8_t * block, uint8_t * extraBlock, int blockSize, int fileSize)
{
  int twoBlocks = 0;
  //l is block size in bits
  uint64_t l = (uint64_t)fileSize * 8;
  if(blockSize <= 55)
  {
    block[blockSize] = 0x80;
    int i;
    for( i = 0; i < 8; i++ )
    {
      block[56+i] = (l >> (56-(8*i)));
    }
  }
  else
  {
    twoBlocks = 1;
    if(blockSize < 63)
      block[blockSize] = 0x80;
    else
      extraBlock[0] = 0x80;

    int i;
    for( i = 0; i < 8; i++ )
    {
      extraBlock[56+i] = (l >> (56-(8*i)));
    }
  }
  return twoBlocks;
}

void doSha1(uint8_t * block)
{
  static uint32_t w[80] = {0x00000000};
  int i;
  for( i = 0; i < 16; i++ )
  {
    int offset = (i*4);
    w[i] =  block[offset]     << 24 |
      block[offset + 1] << 16 |
      block[offset + 2] << 8  |
      block[offset + 3];
  }

  for( i = 16; i < 80; i++ )
  {
    uint32_t tmp = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]);
    w[i] = rotl( tmp, 1 );
  }

  uint32_t a = H[0];
  uint32_t b = H[1];
  uint32_t c = H[2];
  uint32_t d = H[3];
  uint32_t e = H[4];

  for( i = 0; i < 80; i++ )
  {
    uint32_t tmp = rotl(a, 5) + roundFunc(b,c,d,i) + e + w[i] + kForRound(i);
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = tmp;
  }

  H[0] = H[0] + a;
  H[1] = H[1] + b;
  H[2] = H[2] + c;
  H[3] = H[3] + d;
  H[4] = H[4] + e;
}


int sha1(const unsigned char* input, uint32_t len, unsigned char* output)
{
  sha1_init();

  uint32_t i = 0;

  while (i+64 < len)
  {
    memcpy(block, input+i, 64);
    doSha1(block);
    i += 64;
  }
  if (i < len)
  {
    memcpy(block, input+i, len-i);
    uint32_t done = len-i;
    uint32_t j;
    for (j = done; j < 64; ++j)
      block[j] = extra_block[j] = 0x00;
    int twoBlocks = pad(block, extra_block, done, len);
    doSha1(block);
    if(twoBlocks == 1)
    {
      doSha1(extra_block);
    }
  }
  memset(output, 0, 20);
  for (i = 0; i < 5; ++i)
  {
    uint32_t x = htonl(H[i]);
    memcpy(output+4*i, &x, 4);
  }
  return 0;
}

int sha1_uint8_t(const uint8_t* input, uint32_t len, uint8_t* output)
{
  return sha1((const unsigned char*)input, len, (unsigned char*)output);
}

uint8_t* sha1_with_malloc(const unsigned char* input, uint32_t len)
{
  uint8_t* output = malloc(SHA1_HASH_LEN);
  if (sha1(input, len, output) != 0) return NULL;
  return output;
}
uint8_t* sha1_uint8_t_with_malloc(const uint8_t* input, uint32_t len)
{
  uint8_t* output = malloc(SHA1_HASH_LEN);
  if (sha1_uint8_t(input, len, output) != 0) return NULL;
  return output;
}


#ifdef SHA1_MAIN
int main()
{
  unsigned char input[] = "I wonder if it will work";
  //unsigned char input[] = "SHA-1 MGF1"; 
  unsigned char output[20];
  sha1_init();
  sha1(input, sizeof input - 1, output);

  int i;
  for (i = 0; i < 20; i++)
    printf("%02x", output[i]);
  printf("\n");
}
#endif
