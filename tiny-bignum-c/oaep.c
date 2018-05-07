#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "oaep.h"

#include "sha1.h"
#include "rsa.h"
#include "bn.h"

static const unsigned char params[] = "SHA-1 MGF1";

static void fill_random(uint8_t* seed, uint32_t hLen)
{
  uint32_t i;
  for (i = 0; i < hLen; ++i)
  seed[i] = rand();
}

uint8_t* pkcs_mgf1(uint8_t* seed, uint32_t seedOffset, uint32_t seedLength, uint32_t desiredLength)
{
  uint32_t hLen = 20;
  uint32_t offset = 0;
  uint32_t i = 0;

  uint8_t* mask = malloc(desiredLength);
  uint8_t* temp = malloc(seedLength+4);
  uint8_t* sha1_buf = malloc(SHA1_HASH_LEN);
  memcpy(temp+4, seed+seedOffset, seedLength);
  while (offset < desiredLength)
  {
    temp[0] = (uint8_t) ((i >> 24) & 255);
    temp[1] = (uint8_t) ((i >> 16) & 255);
    temp[2] = (uint8_t) ((i >> 8) & 255);
    temp[3] = (uint8_t) (i & 255);
    
    uint32_t remaining = desiredLength - offset;
    sha1_uint8_t(temp, seedLength+4, sha1_buf);
    memcpy(mask+offset, sha1_buf, remaining < hLen ? remaining : hLen);
    offset += hLen;
    ++i;
  }
  free(sha1_buf);
  free(temp);

  return mask;
}

uint8_t* pkcs_oaep_mgf1_encode(const uint8_t* message, uint32_t mLen, uint32_t length)
{
  uint32_t hLen = SHA1_HASH_LEN;
  if (mLen > length - (hLen << 1) - 1)
  {
    printf("Message Too Long\n");
    return NULL;
  }

  uint8_t* sha1_buf = malloc(SHA1_HASH_LEN);
  uint32_t zeroPad = length - mLen - (hLen << 1) - 1;
  uint8_t* dataBlock = malloc(length - hLen);
  
  sha1(params, sizeof params - 1, sha1_buf);
  memcpy(dataBlock, sha1_buf, hLen);
  memcpy(dataBlock + hLen + zeroPad + 1, message, mLen);
  dataBlock[hLen + zeroPad] = 0x01;
  
  uint8_t* seed = malloc(hLen);
  fill_random(seed, hLen);
  
  uint8_t* dataBlockMask = pkcs_mgf1(seed, 0, hLen, length - hLen);
  for (uint32_t i = 0; i < length - hLen; ++i)
    dataBlock[i] ^= dataBlockMask[i];
  
  uint8_t* seedMask = pkcs_mgf1(dataBlock, 0, length - hLen, hLen);
  for (uint32_t i = 0; i < hLen; ++i)
    seed[i] ^= seedMask[i];
  
  uint8_t* padded = malloc(length);
  memset(padded, 0, length);
  memcpy(padded, seed, hLen);
  memcpy(padded + hLen, dataBlock, length - hLen);

  free(sha1_buf);
  free(dataBlock);
  free(seed);
  free(dataBlockMask);
  free(seedMask);

  return padded;
}


uint8_t* pkcs_oaep_mgf1_decode(const uint8_t* message, uint32_t mLen)
{
  uint32_t hLen = SHA1_HASH_LEN;
  if (mLen < (hLen << 1) + 1)
  {
    printf("95. Invalid OAEP MGF1 format.");
    return NULL;
  }

  uint8_t* copy = malloc(mLen);
  memcpy(copy, message, mLen);
  
  uint8_t* seedMask = pkcs_mgf1(copy, hLen, mLen - hLen, hLen);
  for (uint32_t i = 0; i < hLen; ++i)
    copy[i] ^= seedMask[i];
 
  uint8_t* paramsHash = sha1_with_malloc(params, sizeof params - 1);
  uint8_t* dataBlockMask = pkcs_mgf1(copy, 0, hLen, mLen - hLen);
  int32_t index = -1;
  for (uint32_t i = hLen; i < mLen; ++i)
  {
    copy[i] ^= dataBlockMask[i - hLen];
    if (i < (hLen << 1) && copy[i] != paramsHash[i - hLen])
    {
        printf("113. Invalid OAEP MFG1 format.");
        return NULL;
    } else if (index == -1 && copy[i] == 1)
    {
      index = i+1;
    }
  }

  if (index == -1 || index == (int32_t)mLen)
  {
    printf("119. Invalid OAEP MFG1 format.");
    return NULL;
  }
  uint8_t* unpadded = malloc(mLen - index);
  memset(unpadded, 0, mLen - index);
  memcpy(unpadded, copy + index, mLen - index);
  
  free(copy);
  free(seedMask);
  free(paramsHash);
  free(dataBlockMask);

  return unpadded;
}

#if defined(OAEP_MAIN)
int main() {
  unsigned char input[] = "I wonder if it will work";
  uint8_t* encoded = pkcs_oaep_mgf1_encode(input, sizeof input - 1, 256);
  printf("Encoded:\n");
  for (int i = 0; i < 256; ++i)
    printf("%02x", encoded[i]);
  printf("\n");

  uint8_t* decoded = pkcs_oaep_mgf1_decode(encoded, 256);
  printf("Decoded:\n");
  for (uint32_t i = 0; i < sizeof input - 1; ++i)
    printf("%c", decoded[i]);
  printf("\n");

  free(encoded);
  free(decoded);
  return 0;
}
#endif

#if defined(TEST2)
int main()
{
  FILE* f = fopen("cipher", "rb");
  unsigned char encoded[256];
  int r = fread(encoded, 1, 256, f);
  if (r < 256) {
    printf("didnt read 256 bytes");
    return 1;
  }
  fclose(f);
  
  uint8_t* decoded = pkcs_oaep_mgf1_decode(encoded, RSA_KEYSIZE);
  printf("decoded: %p", decoded);
  if (!decoded) return 0;
  printf("decoded: "); print_hex(decoded, 256);

  free(decoded);
  return 0;
}
#endif