
#include <stdint.h>
#include <stdlib.h>
// #include <stdio.h>
// #include <string.h>

#include "sha1.h"
#include "rsa.h"
#include "util.h"
#include "bn.h"

#ifdef __H8_2329F__
#include "../sbrk.h"
#endif

  /**
   -----BEGIN RSA PRIVATE KEY-----
   MIIEogIBAAKCAQEA9Pj6wMGCL5DB/zW4F++kYla3DXfhKYJlOjdZhuRRJkPeJpWZstELZgKHvqWn
   PnaK5Iig19OKvv7MpfZZaL5qyqJEU9tGFL96GFu/1XMLV3CUSUkohndwECitZEwjT/+FKwxFNlGU
   e+OjWjSgfSc2+DyfEm9Q13Agz8N/kXmV2omp9WE0BmH8rxozJKwDrflg4kLmSN+5t8qLx83RjHWg
   DCAhI6kDKZCFne7o3hdFfV9x60NbGCdvgvfWXWr5ZrnzP5P9BxS4sxGQTaumiGa1knYqR8a39tyQ
   mjEjFJsBscch//qQe4d3hGIayOwKo/5PGFY2iQoP0yfY/eCjia20sQIDAQABAoIBAEAoZSPOilYC
   x4wbeZdrP9Yxd8ejOekxKWnRzTSy3z3yUGAylgprDV0uFHct01tcmIu57MYZtSDIgriEiG4SUM25
   KcP8jaIpc8SlYtx4QOQpq+x1qJNu/H5+6Mp31lfBSBM6J3ZOb2DzAXlChzW/63mgBtlBJh8GUtGX
   FfX3rfOJzzboecKZDh2g7mfyGKu9X0LIK7tpaGnbxaUERlcCwcXYtjeTDOvIACHsJeBI9Z7oCqtc
   tRWmDRDvATKbTNVD7Rlbfkrw2PdegmuHj3Y5LOmv5Pk1lXU2RR89xGNyNdgxpmnZhmcv/UxjbY0c
   7+3XKj/dILCEBj4SqYCpBo/2e3ECgYEA/SXI7yI9K14gpEsOSA8WbrdEJ+Q6iVgc/8WgfpWZD7Np
   78VVLqygTn0OYchcokFX6rrAxvquiFwRPzuo30Iou21b8Zale/ykdBLuWcS3LWgdQPRGmNwbOGBD
   df1lSq38bzTpSFBKIg8vYpFdXZjSVYcZo7bG9aK1kMe+ee9S/SsCgYEA97udCCvfXPCUMhDpyjW8
   TSWTFH0Hc4B87n63zdB750MEpPwbzVimxoWUG0XzlZMMVkcC1yM2ZseA9UA8ps/mFCAgL53J697S
   3PWu/x7WFcFGQgYVaPszBXSmcqppTSR+LPvevw9nB1uImchQfrTMR39ZFSdEQR2j3ZwN48lKf5MC
   gYAB5oK3qN4ksTQ1h4q358UXV7DfS8tUtKCjGuy1hpH7mDE3Z5fYHdumOzIccdCgNzVdwcEovUEK
   LQbEHsKJyolbvtpt2d+sKp1hcbLwYZWudZWiozLUevKJXc+j1x8njF7UxuTpchDcaJjGeKjmxvrt
   QXJj1D9yIKKUT6uSZsWMuQKBgC4xMWqgo5l00m0zciReOKo5417ioU0MHD9sKWGbCj9o46jPyW9U
   pGRH7AHZ3T16mcZMn172FeK8OHOCcsy33zLJerbmOQxeE/tXZDX1zf1oeG0/LSbSEAVoZtDirZfQ
   wiYpILOHb7KTgrkJ/NhjZeO+/yFOnQ93M2LTAlQC6H05AoGAZgxdgau13nQQIRMpUp8C++fa8BHj
   R0M+rFPzpmCKX+OgE9XvHV385TpGXp+4Ink17mAMWZzsEXpunZX+bCObRYztW9jobZOUxztKDTIW
   WLNthIoIo+e8QbV9lqQnLZv02cV2MG+nZkYa+vBR3ESP/CEge0OlEYVkKFsyH6Bw9aY=
   -----END RSA PRIVATE KEY-----
   */
   


struct heap heap;

#ifdef __H8_2329F__
char HEAP_MEM[HEAP_SIZE];
#endif

static bool init()
{
  heap.size = HEAP_SIZE;
#ifdef __H8_2329F__
  heap.buf = heap.brk = HEAP_MEM;
#else
  heap.buf = heap.brk = malloc(heap.size);
#endif
  if (heap.buf == NULL) return false;

  // srand(1);

  return true;
}


static unsigned char* get_rand(uint32_t count) {
  unsigned char* res = heap_get(count);
  
  //for (uint32_t i = 0; i < count; ++i) res[i] = rand();
  for (uint32_t i = 0; i < count; ++i) res[i] = 1; //                         FIXME ################################
  return res;
}

static void strxor(const unsigned char* s1, const unsigned char* s2, 
                  unsigned char* dest, uint32_t len) {
  for (uint32_t i = 0; i < len; ++i) dest[i] = s1[i] ^ s2[i];
}


unsigned char* mgf(unsigned char* mgfSeed, uint32_t mlen, uint32_t maskLen)
{
  uint32_t len = (maskLen + SHA1_HASH_LEN - 1) / SHA1_HASH_LEN;
  unsigned char* T = heap_get(len * SHA1_HASH_LEN);
  unsigned char* C = heap_get(mlen + 4);
  unsigned char* hash_temp = heap_get(SHA1_HASH_LEN);
  uint32_t i = 0;
  for (; i < (maskLen + SHA1_HASH_LEN - 1) / SHA1_HASH_LEN; ++i)
  {
    uint8_t temp[4];
    temp[0] = (uint8_t) ((i >> 24) & 255);
    temp[1] = (uint8_t) ((i >> 16) & 255);
    temp[2] = (uint8_t) ((i >> 8) & 255);
    temp[3] = (uint8_t) (i & 255);
    memcpy(C, mgfSeed, mlen);
    memcpy(C+mlen, temp, 4);
    sha1(C, mlen + 4, hash_temp);
    memcpy(T + i*SHA1_HASH_LEN, hash_temp, SHA1_HASH_LEN);
  }

  require (i*SHA1_HASH_LEN >= maskLen, "programming error");

  unsigned char* ret = T;
  if (i*SHA1_HASH_LEN > maskLen)
  {
    ret = heap_get(maskLen);
    memcpy(ret, T, maskLen);
    heap_free(len * SHA1_HASH_LEN);
  }

  heap_free(mlen + 4 + SHA1_HASH_LEN);

  return ret;
}

unsigned char* pkcs_oaep_encode(const unsigned char* message, uint32_t mLen)
{
  /*  TODO check if key is RSA */

  const uint32_t k = 256;
  const uint32_t hLen = SHA1_HASH_LEN;

  /*  STEP 1b */
  int32_t ps_len = k - mLen - 2*hLen - 2;
  if (ps_len < 0) {
#if defined(USE_IO) || !defined(__H8_2329F__)
	fprintf(stderr, "Data too long.\n");
#endif
    return NULL;
  }

  const char *brk_start = heap.brk;

  sha1_start();

  /*  STEP 2a */
  unsigned char* lHash = sha1_with_malloc((const unsigned char*)"", 0);
  /*  STEP 2b */
  unsigned char* ps = heap_get(ps_len);
  memset(ps, 0, ps_len);

  /*  STEP 2c */
  uint32_t dbLen = SHA1_HASH_LEN + ps_len + 1 + mLen;
  unsigned char* db = heap_get(dbLen);
  memcpy(db, lHash, SHA1_HASH_LEN);
  memcpy(db + SHA1_HASH_LEN, ps, ps_len);
  *(db + SHA1_HASH_LEN + ps_len) = 0x01;
  memcpy(db + SHA1_HASH_LEN + ps_len + 1, message, mLen);

  /*  STEP 2d */
  unsigned char* ros = get_rand(hLen);

  /*  STEP 2e */
  unsigned char* dbMask = mgf(ros, hLen, k - hLen - 1);

  /*  STEP 2f */
  unsigned char* maskedDb = heap_get(dbLen);
  strxor(db, dbMask, maskedDb, dbLen);

  /*  Step 2g */
  unsigned char* seedMask = mgf(maskedDb, dbLen, hLen);

  /*  Step 2h */
  unsigned char* maskedSeed = heap_get(hLen);
  strxor(ros, seedMask, maskedSeed, hLen);

  /*  Step 2i */
  unsigned char* em = heap_get(1 + hLen + dbLen);
  *em = 0x00;
  memcpy(em+1, maskedSeed, hLen);
  memcpy(em+1+hLen, maskedDb, dbLen);

  heap_free(heap.brk-brk_start);
  
  /*  Step 3a, 3b, 3c */
  //unsigned char* m = pkcs_rsa_encrypt(em, 1 + hLen + dbLen, n, nlen, e);
  //unsigned char *m = rsa_encrypt(em, 1 + hLen + dbLen, n, nlen, e);
  
  return em;
}

unsigned char n_hex[] = "f4f8fac0c1822f90c1ff35b817efa46256b70d77e12982653a375986e4512643de269599b2d10b660287bea5a73e768ae488a0d7d38abefecca5f65968be6acaa24453db4614bf7a185bbfd5730b5770944949288677701028ad644c234fff852b0c453651947be3a35a34a07d2736f83c9f126f50d77020cfc37f917995da89a9f561340661fcaf1a3324ac03adf960e242e648dfb9b7ca8bc7cdd18c75a00c202123a9032990859deee8de17457d5f71eb435b18276f82f7d65d6af966b9f33f93fd0714b8b311904daba68866b592762a47c6b7f6dc909a3123149b01b1c721fffa907b877784621ac8ec0aa3fe4f185636890a0fd327d8fde0a389adb4b1";
  
// public key, unhexlify it first.
//unsigned char n_hex[] = "f4f8fac0c1822f90c1ff35b817efa46256b70d77e12982653a375986e4512643de269599b2d10b660287bea5a73e768ae488a0d7d38abefecca5f65968be6acaa24453db4614bf7a185bbfd5730b5770944949288677701028ad644c234fff852b0c453651947be3a35a34a07d2736f83c9f126f50d77020cfc37f917995da89a9f561340661fcaf1a3324ac03adf960e242e648dfb9b7ca8bc7cdd18c75a00c202123a9032990859deee8de17457d5f71eb435b18276f82f7d65d6af966b9f33f93fd0714b8b311904daba68866b592762a47c6b7f6dc909a3123149b01b1c721fffa907b877784621ac8ec0aa3fe4f185636890a0fd327d8fde0a389adb4b1";
/*
unsigned char n[] = {
	0xf4, 0xf8, 0xfa, 0xc0, 0xc1, 0x82, 0x2f, 0x90,
	0xc1, 0xff, 0x35, 0xb8, 0x17, 0xef, 0xa4, 0x62,
	0x56, 0xb7, 0xd, 0x77, 0xe1, 0x29, 0x82, 0x65,
	0x3a, 0x37, 0x59, 0x86, 0xe4, 0x51, 0x26, 0x43,
	0xde, 0x26, 0x95, 0x99, 0xb2, 0xd1, 0xb, 0x66,
	0x2, 0x87, 0xbe, 0xa5, 0xa7, 0x3e, 0x76, 0x8a,
	0xe4, 0x88, 0xa0, 0xd7, 0xd3, 0x8a, 0xbe, 0xfe,
	0xcc, 0xa5, 0xf6, 0x59, 0x68, 0xbe, 0x6a, 0xca,
	0xa2, 0x44, 0x53, 0xdb, 0x46, 0x14, 0xbf, 0x7a,
	0x18, 0x5b, 0xbf, 0xd5, 0x73, 0xb, 0x57, 0x70,
	0x94, 0x49, 0x49, 0x28, 0x86, 0x77, 0x70, 0x10,
	0x28, 0xad, 0x64, 0x4c, 0x23, 0x4f, 0xff, 0x85,
	0x2b, 0xc, 0x45, 0x36, 0x51, 0x94, 0x7b, 0xe3,
	0xa3, 0x5a, 0x34, 0xa0, 0x7d, 0x27, 0x36, 0xf8,
	0x3c, 0x9f, 0x12, 0x6f, 0x50, 0xd7, 0x70, 0x20,
	0xcf, 0xc3, 0x7f, 0x91, 0x79, 0x95, 0xda, 0x89,
	0xa9, 0xf5, 0x61, 0x34, 0x6, 0x61, 0xfc, 0xaf,
	0x1a, 0x33, 0x24, 0xac, 0x3, 0xad, 0xf9, 0x60,
	0xe2, 0x42, 0xe6, 0x48, 0xdf, 0xb9, 0xb7, 0xca,
	0x8b, 0xc7, 0xcd, 0xd1, 0x8c, 0x75, 0xa0, 0xc,
	0x20, 0x21, 0x23, 0xa9, 0x3, 0x29, 0x90, 0x85,
	0x9d, 0xee, 0xe8, 0xde, 0x17, 0x45, 0x7d, 0x5f,
	0x71, 0xeb, 0x43, 0x5b, 0x18, 0x27, 0x6f, 0x82,
	0xf7, 0xd6, 0x5d, 0x6a, 0xf9, 0x66, 0xb9, 0xf3,
	0x3f, 0x93, 0xfd, 0x7, 0x14, 0xb8, 0xb3, 0x11,
	0x90, 0x4d, 0xab, 0xa6, 0x88, 0x66, 0xb5, 0x92,
	0x76, 0x2a, 0x47, 0xc6, 0xb7, 0xf6, 0xdc, 0x90,
	0x9a, 0x31, 0x23, 0x14, 0x9b, 0x1, 0xb1, 0xc7,
	0x21, 0xff, 0xfa, 0x90, 0x7b, 0x87, 0x77, 0x84,
	0x62, 0x1a, 0xc8, 0xec, 0xa, 0xa3, 0xfe, 0x4f,
	0x18, 0x56, 0x36, 0x89, 0xa, 0xf, 0xd3, 0x27,
	0xd8, 0xfd, 0xe0, 0xa3, 0x89, 0xad, 0xb4, 0xb1
};
uint32_t e = 0x10001;
*/

int main()
{
  if (!init()) {
#if defined(USE_IO)
    fprintf(stderr, "init failed\n");
#endif
    return 1;
  }

  unsigned char input[] = "I wonder if it will work";
  /*  unsigned char d_hex[] = "40286523ce8a5602c78c1b79976b3fd63177c7a339e9312969d1cd34b2df3df2506032960a6b0d5d2e14772dd35b5c988bb9ecc619b520c882b884886e1250cdb929c3fc8da22973c4a562dc7840e429abec75a8936efc7e7ee8ca77d657c148133a27764e6f60f30179428735bfeb79a006d941261f0652d19715f5f7adf389cf36e879c2990e1da0ee67f218abbd5f42c82bbb696869dbc5a504465702c1c5d8b637930cebc80021ec25e048f59ee80aab5cb515a60d10ef01329b4cd543ed195b7e4af0d8f75e826b878f76392ce9afe4f935957536451f3dc4637235d831a669d986672ffd4c636d8d1cefedd72a3fdd20b084063e12a980a9068ff67b71"; */
  uint32_t e = 0x10001;
  
  unsigned char *n = heap_get(256);
  unhexlify(n_hex, 512, n);
  // encryption
  unsigned char *oaep_encoding = pkcs_oaep_encode(input, sizeof input - 1);
  unsigned char *cipher = rsa_encrypt(oaep_encoding, 256, n, RSA_KEYSIZE, e);
  // free_heap(256);
  
  if (!cipher) {
    /*  Problem with Data / Key or malloc failed to reserve memory */
#if defined(USE_IO) || !defined(__H8_2329F__)
	printf("Can't make this cipher.\n");
#endif
  } else {
#if defined(USE_IO) || !defined(__H8_2329F__)
  printf("cipher: ");
  print_hex(cipher, RSA_KEYSIZE); printf("\n");
#endif
  }
  

#ifndef __H8_2329F__
  free(heap.buf);
#endif
  return 0;
}
