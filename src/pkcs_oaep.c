
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sha1.h"
#include "rsa.h"
#include "util.h"

static unsigned char* get_rand(uint32_t count)
{
     static int srand_made = 0;
     if (!srand_made)
     srand(1);

  unsigned char* res = malloc(count);
     for (uint32_t i = 0; i < count; ++i)
     res[i] = rand();
  return res;
}

static void strxor(const unsigned char* s1,
    const unsigned char* s2,
    unsigned char* dest,
    uint32_t len)
{
  uint32_t i;
  for (i = 0; i < len; ++i)
    dest[i] = s1[i] ^ s2[i];
}

unsigned char* pkcs_rsa_encrypt(const unsigned char* message,
    uint32_t mLen,
    const unsigned char* n,
    uint32_t nLen,
    uint32_t e)
{
  /*  step 3a, 3b, 3c */
  return rsa_encrypt(message, mLen, n, nLen, e);
}

unsigned char* mgf(unsigned char* mgfSeed, uint32_t mlen, uint32_t maskLen)
{
  uint32_t len = (maskLen + SHA1_HASH_LEN - 1) / SHA1_HASH_LEN;
  unsigned char* T = malloc(len * SHA1_HASH_LEN);
  unsigned char* C = malloc(mlen + 4);
  unsigned char* hash_temp = malloc(SHA1_HASH_LEN);
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
    ret = malloc(maskLen);
    memcpy(ret, T, maskLen);
    free(T);
  }

  free(C);
  free(hash_temp);

  return ret;
}

/**
 * Main function of the encryption
 * PARAMS:
 * message: bytes of the message to encrypt in Big Endian (Network Number Representation).
 * mLen: length of the message in bytes
 * n: bytes representation of the Modulus N in Big Endian.
 * nlen: length of n (THIS should be 256 in RSA2048 encryption)
 * e: public exponent (uint32_t should be enough)
 * 
 * RETURN:
 * PKCS1_OAEP encryption of the message in Big Endian.
 */

unsigned char* pkcs_oaep(const unsigned char* message,
    uint32_t mLen,
    const unsigned char* n,
    uint32_t nlen,
    uint32_t e)
{
  /*  TODO check if key is RSA */

  const uint32_t k = 256;
  const uint32_t hLen = SHA1_HASH_LEN;

  /*  STEP 1b */
  int32_t ps_len = k - mLen - 2*hLen - 2;
  if (ps_len < 0) {
    /*  printf("Data too long.\n"); */
    return NULL;
  }

  /*  STEP 2a */
  unsigned char* lHash = sha1_with_malloc((const unsigned char*)"", 0);
  /*  STEP 2b */
  unsigned char* ps = calloc(ps_len, 1);

  /*  STEP 2c */
  uint32_t dbLen = SHA1_HASH_LEN + ps_len + 1 + mLen;
  unsigned char* db = malloc(dbLen);
  memcpy(db, lHash, SHA1_HASH_LEN);
  memcpy(db + SHA1_HASH_LEN, ps, ps_len);
  *(db + SHA1_HASH_LEN + ps_len) = 0x01;
  memcpy(db + SHA1_HASH_LEN + ps_len + 1, message, mLen);

  /*  STEP 2d */
  unsigned char* ros = get_rand(hLen);

  /*  STEP 2e */
  unsigned char* dbMask = mgf(ros, hLen, k - hLen - 1);

  /*  STEP 2f */
  unsigned char* maskedDb = malloc(dbLen);
  strxor(db, dbMask, maskedDb, dbLen);

  /*  Step 2g */
  unsigned char* seedMask = mgf(maskedDb, dbLen, hLen);

  /*  Step 2h */
  unsigned char* maskedSeed = malloc(hLen);
  strxor(ros, seedMask, maskedSeed, hLen);

  /*  Step 2i */
  unsigned char* em = malloc(1 + hLen + dbLen);
  *em = 0x00;
  memcpy(em+1, maskedSeed, hLen);
  memcpy(em+1+hLen, maskedDb, dbLen);

  /*  printf("oaep encoding: "); print_hex(em, RSA_KEYSIZE); */

  free(lHash);
  free(ps);
  free(db);
  free(ros);
  free(dbMask);
  free(maskedDb);
  free(seedMask);
  free(maskedSeed);

  /*  Step 3a, 3b, 3c */
  unsigned char* m = pkcs_rsa_encrypt(em, 1 + hLen + dbLen, n, nlen, e);

  free(em);

  return m;

}



int main()
{
  /**
   * RSA arguments: N and e
   * we feed N in hex format, but it is not required for the encryption.
   * used key for the example (PEM format): 
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
   *
   * 
   * NOTE: the program doesn't support importing keys from PEM and DER format.
   * ATTENTION: this encryption is implemented according to RFC 3447 Section 7.1 (https:// tools.ietf.org/html/rfc3447#section-7.1) //
   *           However, It works correctly only with valid input (errors handling not managed yet).
   *           So Make sure to always check your (key / input).
   */

  unsigned char n_hex[] = "f4f8fac0c1822f90c1ff35b817efa46256b70d77e12982653a375986e4512643de269599b2d10b660287bea5a73e768ae488a0d7d38abefecca5f65968be6acaa24453db4614bf7a185bbfd5730b5770944949288677701028ad644c234fff852b0c453651947be3a35a34a07d2736f83c9f126f50d77020cfc37f917995da89a9f561340661fcaf1a3324ac03adf960e242e648dfb9b7ca8bc7cdd18c75a00c202123a9032990859deee8de17457d5f71eb435b18276f82f7d65d6af966b9f33f93fd0714b8b311904daba68866b592762a47c6b7f6dc909a3123149b01b1c721fffa907b877784621ac8ec0aa3fe4f185636890a0fd327d8fde0a389adb4b1";
  /*  unsigned char d_hex[] = "40286523ce8a5602c78c1b79976b3fd63177c7a339e9312969d1cd34b2df3df2506032960a6b0d5d2e14772dd35b5c988bb9ecc619b520c882b884886e1250cdb929c3fc8da22973c4a562dc7840e429abec75a8936efc7e7ee8ca77d657c148133a27764e6f60f30179428735bfeb79a006d941261f0652d19715f5f7adf389cf36e879c2990e1da0ee67f218abbd5f42c82bbb696869dbc5a504465702c1c5d8b637930cebc80021ec25e048f59ee80aab5cb515a60d10ef01329b4cd543ed195b7e4af0d8f75e826b878f76392ce9afe4f935957536451f3dc4637235d831a669d986672ffd4c636d8d1cefedd72a3fdd20b084063e12a980a9068ff67b71"; */
  uint32_t e = 0x10001;
  /* unsigned char n[] = "\xf4\xf8\xfa\xc0\xc1\x82/\x90\xc1\xff5\xb8\x17\xef\xa4bV\xb7\rw\xe1)\x82e:7Y\x86\xe4Q&C\xde&\x95\x99\xb2\xd1\x0bf\x02\x87\xbe\xa5\xa7>v\x8a\xe4\x88\xa0\xd7\xd3\x8a\xbe\xfe\xcc\xa5\xf6Yh\xbej\xca\xa2DS\xdbF\x14\xbfz\x18[\xbf\xd5s\x0bWp\x94II(\x86wp\x10(\xaddL#O\xff\x85+\x0cE6Q\x94{\xe3\xa3Z4\xa0}'6\xf8<\x9f\x12oP\xd7p \xcf\xc3\x7f\x91y\x95\xda\x89\xa9\xf5a4\x06a\xfc\xaf\x1a3$\xac\x03\xad\xf9`\xe2B\xe6H\xdf\xb9\xb7\xca\x8b\xc7\xcd\xd1\x8cu\xa0\x0c !#\xa9\x03)\x90\x85\x9d\xee\xe8\xde\x17E}_q\xebC[\x18'o\x82\xf7\xd6]j\xf9f\xb9\xf3?\x93\xfd\x07\x14\xb8\xb3\x11\x90M\xab\xa6\x88f\xb5\x92v*G\xc6\xb7\xf6\xdc\x90\x9a1#\x14\x9b\x01\xb1\xc7!\xff\xfa\x90{\x87w\x84b\x1a\xc8\xec\n\xa3\xfeO\x18V6\x89\n\x0f\xd3'\xd8\xfd\xe0\xa3\x89\xad\xb4\xb1"; */
  /* unsigned char d[] = "@(e#\xce\x8aV\x02\xc7\x8c\x1by\x97k?\xd61w\xc7\xa39\xe91)i\xd1\xcd4\xb2\xdf=\xf2P`2\x96\nk\r].\x14w-\xd3[\\\x98\x8b\xb9\xec\xc6\x19\xb5 \xc8\x82\xb8\x84\x88n\x12P\xcd\xb9)\xc3\xfc\x8d\xa2)s\xc4\xa5b\xdcx@\xe4)\xab\xecu\xa8\x93n\xfc~~\xe8\xcaw\xd6W\xc1H\x13:'vNo`\xf3\x01yB\x875\xbf\xeby\xa0\x06\xd9A&\x1f\x06R\xd1\x97\x15\xf5\xf7\xad\xf3\x89\xcf6\xe8y\xc2\x99\x0e\x1d\xa0\xeeg\xf2\x18\xab\xbd_B\xc8+\xbbihi\xdb\xc5\xa5\x04FW\x02\xc1\xc5\xd8\xb67\x93\x0c\xeb\xc8\x00!\xec%\xe0H\xf5\x9e\xe8\n\xab\\\xb5\x15\xa6\r\x10\xef\x012\x9bL\xd5C\xed\x19[~J\xf0\xd8\xf7^\x82k\x87\x8fv9,\xe9\xaf\xe4\xf95\x95u6E\x1f=\xc4cr5\xd81\xa6i\xd9\x86g/\xfdLcm\x8d\x1c\xef\xed\xd7*?\xdd \xb0\x84\x06>\x12\xa9\x80\xa9\x06\x8f\xf6{q"; */

  unsigned char input[] = "I wonder if it will work";

  /*  convert n from hex encoding to bytes directly: required only if you used hex encoding to fill N. */
  unsigned char* n_bytes = malloc(RSA_KEYSIZE);
  unhexlify(n_hex, sizeof n_hex - 1, n_bytes);

  /*  encryption */
  unsigned char* cipher = pkcs_oaep(input, sizeof input - 1, n_bytes, RSA_KEYSIZE, e);
  if (!cipher) {
    /*  Problem with Data / Key or malloc failed to reserve memory */
    printf("Can't make this cipher.\n");
    return 1;
  }

  printf("cipher: ");
  print_hex(cipher, RSA_KEYSIZE); printf("\n");

  free(n_bytes);
  free(cipher);
  return 0;
}
