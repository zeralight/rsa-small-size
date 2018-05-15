#ifndef __BIGNUM_H__
#define __BIGNUM_H__

#include <stdint.h>
#include <stdbool.h>

#include "util.h"

#define WORD_SIZE 2

/* This macro defines the word size in bytes of the array that constitues the big-number data structure.*/
#ifndef WORD_SIZE
  #define WORD_SIZE 4
#endif

/* Size of big-numbers in bytes*/
#define BN_ARRAY_SIZE    (512 / WORD_SIZE)


/* Here comes the compile-time specialization for how large the underlying array size should be.*/
/* The choices are 1, 2 and 4 bytes in size with uint32, uint64 for WORD_SIZE==4, as temporary.*/
#ifndef WORD_SIZE
  #error Must define WORD_SIZE to be 1, 2, 4
#elif (WORD_SIZE == 1)
  /* Data type of array in structure*/
  #define DTYPE                    uint8_t
  /* bitmask for getting MSB*/
  #define DTYPE_MSB                ((DTYPE_TMP)(0x80))
  /* Data-type larger than DTYPE, for holding intermediate results of calculations*/
  #define DTYPE_TMP                uint32_t
  /* sprintf format string*/
  #define SPRINTF_FORMAT_STR       "%.02x"
  #define SSCANF_FORMAT_STR        "%2hhx"
  /* Max value of integer type*/
  #define MAX_VAL                  ((DTYPE_TMP)0xFF)
#elif (WORD_SIZE == 2)
  #define DTYPE                    uint16_t
  #define DTYPE_TMP                uint32_t
  #define DTYPE_MSB                ((DTYPE_TMP)(0x8000))
  #define SPRINTF_FORMAT_STR       "%.04x"
  #define SSCANF_FORMAT_STR        "%4hx"
  #define MAX_VAL                  ((DTYPE_TMP)0xFFFF)
#elif (WORD_SIZE == 4)
  #define DTYPE                    uint32_t
  #define DTYPE_TMP                uint64_t
  #define DTYPE_MSB                ((DTYPE_TMP)(0x80000000))
  #define SPRINTF_FORMAT_STR       "%.08x"
  #define SSCANF_FORMAT_STR        "%8x"
  #define MAX_VAL                  ((DTYPE_TMP)0xFFFFFFFF)
#endif
#ifndef DTYPE
  #error DTYPE must be defined to uint8_t, uint16_t uint32_t or whatever
#endif



/* Data-holding structure: array of DTYPEs*/
struct bn
{
  DTYPE array[BN_ARRAY_SIZE];
  uint16_t len;
};

struct karatsuba_ctx
{
  struct bn *pool;
  uint16_t idx;
};

extern struct karatsuba_ctx karatsuba_ctx;

/* Tokens returned by bignum_cmp() for value comparison*/
enum { SMALLER = -1, EQUAL = 0, LARGER = 1 };



/* Initialization functions:*/
void bignum_init(struct bn* n); /* required*/
void bignum_from_int(struct bn* n, DTYPE_TMP i); /* required*/
// uint32_t  bignum_to_int(struct bn* n);
// void bignum_from_string(struct bn* n, char* str, int nbytes);
// void bignum_to_string(struct bn* n, char* str, int maxsize);
void bignum_to_bytes(const struct bn* n, unsigned char* bytes, uint32_t len); /* required*/
void bignum_from_bytes(struct bn* n, const unsigned char* bytes, uint32_t len); /* required*/

/* Basic arithmetic operations:*/
void bignum_add(struct bn* a, struct bn* b, struct bn* c); /* c = a + b*/ /* required*/
void bignum_sub(struct bn* a, struct bn* b, struct bn* c); /* c = a - b*/ /* required*/
void bignum_mul_naive(struct bn*, struct bn*, struct bn*);
void bignum_mul_karatsuba(struct bn*, struct bn*, struct bn*);
#ifdef NAIVE_MUL
#define bignum_mul(a, b, c) bignum_mul_naive((a), (b), (c))
#else
#define bignum_mul(a, b, c) bignum_mul_karatsuba((a), (b), (c))
#endif
void bignum_div(struct bn* a, struct bn* b, struct bn* c); /* c = a / b*/ /* required*/
void bignum_mod(struct bn* a, struct bn* b, struct bn* c); /* c = a % b*/ /* required*/

/* Bitwise operations:*/
// void bignum_and(struct bn* a, struct bn* b, struct bn* c); /* c = a & b*/
void bignum_or(struct bn* a, struct bn* b, struct bn* c);  /* c = a | b*/ /* required*/
// void bignum_xor(struct bn* a, struct bn* b, struct bn* c); /* c = a ^ b*/
void bignum_lshift(struct bn* a, struct bn* b, int nbits); /* b = a << nbits*/
void bignum_rshift(struct bn* a, struct bn* b, int nbits); /* b = a >> nbits*/

/* Special operators and comparison*/
int  bignum_cmp(struct bn* a, struct bn* b);               /* Compare: returns LARGER, EQUAL or SMALLER*/
#define bignum_is_zero(n) (!((n)->len))
//int  bignum_is_zero(struct bn* n);                         /* For comparison with zero*/ /* required*/
// void bignum_inc(struct bn* n);                             /* Increment: add one to n*/
// void bignum_dec(struct bn* n);                             /* Decrement: subtract one from n*/
void bignum_pow(struct bn* a, struct bn* b, struct bn* c); /* Calculate a^b -- e.g. 2^10 => 1024*/
void bignum_assign(struct bn* dst, const struct bn* src);        /* Copy src into dst -- dst := src*/ /* required*/

void print_arr(const struct bn*);
  
#endif /* #ifndef __BIGNUM_H__*/


