/*

   Big number library - arithmetic on multiple-precision unsigned integers.

   This library is an implementation of arithmetic on arbitrarily large integers.

   The difference between this and other implementations, is that the data structure
   has optimal memory utilization (i.e. a 1024 bit integer takes up 128 bytes RAM),
   and all memory is allocated statically: no dynamic allocation for better or worse.

   Primary goals are correctness, clarity of code and clean, portable implementation.
   Secondary goal is a memory footprint small enough to make it suitable for use in
   embedded applications.


   The current state is correct functionality and adequate performance.
   There may well be room for performance-optimizations and improvements.

 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "bn.h"
#include "sha1.h"
#include "util.h"

/* Functions for shifting number in-place. */
static void _lshift_one_bit(struct bn* a);
static void _rshift_one_bit(struct bn* a);
static void _lshift_word(struct bn* a, int nwords);
static void _rshift_word(struct bn* a, int nwords);
static void bignum_add_unsigned(struct bn* a, struct bn* b, struct bn* c);
static void bignum_sub_unsigned(struct bn* a, struct bn* b, struct bn* c);
static void bignum_dec_unsigned(struct bn* a);
static void bignum_inc_unsigned(struct bn* a);
static int bignum_cmp_unsigned(struct bn* a, struct bn* b);
static void bignum_shift_10(struct bn* a, uint16_t k);
static uint16_t bignum_len(const struct bn* a);
static void bignum_mul_naive(const struct bn*, const struct bn*, struct bn*);

/* Public / Exported functions. */
void bignum_init(struct bn* n)
{
    require(n, "n is null");

    // memset(n->array, 0, BN_ARRAY_SIZE*WORD_SIZE);
    n->negative = false;
    n->len = 0;
}

void bignum_from_int(struct bn* n, DTYPE_TMP i)
{
    require(n, "n is null");

    bignum_init(n);

    /* Endianness issue if machine is not little-endian? */
#ifdef WORD_SIZE
#if (WORD_SIZE == 1)
    n->array[0] = (i & 0x000000ff);
    n->array[1] = (i & 0x0000ff00) >> 8;
    n->array[2] = (i & 0x00ff0000) >> 16;
    n->array[3] = (i & 0xff000000) >> 24;
#elif (WORD_SIZE == 2)
    n->array[0] = (i & 0x0000ffff);
    n->array[1] = (i & 0xffff0000) >> 16;
    n->len = 2;
#elif (WORD_SIZE == 4)
    n->array[0] = i;
    DTYPE_TMP num_32 = 32;
    DTYPE_TMP tmp = i >> num_32; /* bit-shift with U64 operands to force 64-bit results */
    n->array[1] = tmp;
#endif
#endif
}


#ifdef IMPLEMENT_ALL
uint32_t bignum_to_int(struct bn* n)
{
    require(n, "n is null");
    require (!n->negative, "not implemented");

    if (n->len == 0)
        return 0;

    uint32_t ret = 0;
    /* Endianness issue if machine is not little-endian? */
#if (WORD_SIZE == 1)
    ret += n->array[0];
    ret += n->array[1] << 8;
    ret += n->array[2] << 16;
    ret += n->array[3] << 24;  
#elif (WORD_SIZE == 2)
    ret += n->array[0];
    if (n->len > 1)
        ret += n->array[1] << 16;
#elif (WORD_SIZE == 4)
    ret += n->array[0];
#endif

    return ret;
}


void bignum_from_string(struct bn* n, char* str, int nbytes)
{
    require(n, "n is null");
    require(str, "str is null");
    require(nbytes > 0, "nbytes must be positive");
    require((nbytes & 1) == 0, "string format must be in hex -> equal number of bytes");

    bignum_init(n);

    DTYPE tmp;                        /* DTYPE is defined in bn.h - uint{8,16,32,64}_t */
    int i = nbytes - (2 * WORD_SIZE); /* index into string */
    int j = 0;                        /* index into array */

    /* reading last hex-byte "MSB" from string first -> big endian */
    /* MSB ~= most significant byte / block ? :) */
    while (i >= 0)
    {
        tmp = 0;
        sscanf(&str[i], SSCANF_FORMAT_STR, &tmp);
        n->array[j] = tmp;
        i -= (2 * WORD_SIZE); /* step WORD_SIZE hex-byte(s) back in the string. */
        j += 1;               /* step one element forward in the array. */
    }
    n->len = j;
}


void bignum_to_string(struct bn* n, char* str, int nbytes)
{
    require(n, "n is null");
    require(str, "str is null");
    require(nbytes > 0, "nbytes must be positive");
    require((nbytes & 1) == 0, "string format must be in hex -> equal number of bytes");
    require (!n->negative, "only unsigned numbers can be converted to string");
    int j = BN_ARRAY_SIZE - 1; /* index into array - reading "MSB" first -> big-endian */
    int i = 0;                 /* index into string representation. */

    /* reading last array-element "MSB" first -> big endian */
    while ((j >= 0) && (nbytes > (i + 1)))
    {
        sprintf(&str[i], SPRINTF_FORMAT_STR, n->array[j]);
        i += (2 * WORD_SIZE); /* step WORD_SIZE hex-byte(s) forward in the string. */
        j -= 1;               /* step one element back in the array. */
        /* printf("(%d, %d) ", i, j); */
    }
    /* Count leading zeros: */
    j = 0;
    while (str[j] == '0')
    {
        j += 1;
    }

    /* Move string j places ahead, effectively skipping leading zeros */ 
    for (i = 0; i < (nbytes - j); ++i)
    {
        str[i] = str[i + j];
    }

    /* Zero-terminate string */
    str[i] = 0;
}
#endif

void  bignum_to_bytes(const struct bn* n, unsigned char* bytes, uint32_t nbytes)
{
    require(n, "n is null");
    require(bytes, "str is null");
    require(nbytes > 0, "nbytes must be positive");
    require(!n->negative, "only unsigned numbers supported");

    memset(bytes, 0, nbytes);
    
    /*
    uint32_t i;
    for ( i = BN_ARRAY_SIZE; i-- && n->array[i] == 0;);
    */
    uint32_t i = n->len;
    uint32_t internal_len = i*WORD_SIZE;
    unsigned char* internal = malloc(internal_len);
    uint32_t j = 0;
    for (; i--; ++j) {
        DTYPE d;
        i2osp(&d, n->array+i, WORD_SIZE);
        memcpy(internal+j*WORD_SIZE, &d, WORD_SIZE);
        memcpy(&d, internal+j*WORD_SIZE, WORD_SIZE);
    }

    //require (nbytes <= internal_len, "not enough space");
    if (nbytes < internal_len)
        memcpy(bytes, internal + internal_len - nbytes, nbytes);
    else
        memcpy(bytes, internal, internal_len);
        
    free(internal);
}

void bignum_from_bytes(struct bn* n, const unsigned char* bytes, uint32_t nbytes)
{
    require(n, "n is null");
    require(bytes, "bytes is null");
    require(nbytes > 0, "nbytes null");

    bignum_init(n);
    uint32_t i = 0;
    uint32_t j = nbytes;
    /* printf("bignum_from_bytes start: \n"); */
    while (j)
    {
        uint32_t p = j >= WORD_SIZE ? j - WORD_SIZE : 0;
        DTYPE d = 0;
        uint32_t k;
        for (k = p; k < j; ++k)
        {
            /* printf("bignum_from_bytes: reading byte %d\n", bytes[k]); */
            d += bytes[k];
            if (k+1 < j)
                d <<= 8;
        }
        /* printf("bignum_from_bytes: read word: %d\n", d); */
        j = p;
        n->array[i++] = d;
    }
    n->len = i;
}

#ifdef IMPLEMENT_ALL
static void bignum_inc_unsigned(struct bn* n)
{
    require(n, "n is null");

    if (bignum_is_zero(n))
    {
        n->array[0] = 1;
        n->negative = false;
        n->len = 1;
        return;
    }

    DTYPE res;
    DTYPE_TMP tmp; /* copy of n */
    int i;
    for (i = 0; i <= n->len; ++i)
    {
        tmp = n->array[i];
        res = tmp + 1;
        n->array[i] = res;

        if (res > tmp)
        {
            break;
        }
    }
    if (i == n->len+1 && n->array[n->len])
        ++n->len;
}

static void bignum_dec_unsigned(struct bn* n)
{
    require(n, "n is null");

    if (bignum_is_zero(n))
    {
        n->array[0] = 1;
        n->negative = true;
        n->len = 1;
        return;
    }

    DTYPE tmp; /* copy of n */
    DTYPE res;

    int i;
    for (i = 0; i < n->len; ++i)
    {
        tmp = n->array[i];
        res = tmp - 1;
        n->array[i] = res;

        if (!(res > tmp))
        {
            break;
        }
    }
    if (i == n->len)
    {
        for (; i >= 0 && n->array[i] == 0; --i);
        n->len = i+1;
    }
}

void bignum_inc(struct bn* n)
{
    require (n, "n is null");

    if (n->negative)
    {
        bignum_dec_unsigned(n);
        if (bignum_is_zero(n))
            n->negative = false;
    }
    else
    {
        bignum_inc_unsigned(n);
    }
}

void bignum_dec(struct bn* n)
{
    require (n, "n is null");
    
    if (n->negative)
    {
        bignum_inc_unsigned(n);
        if (bignum_is_zero(n))
            n->negative = false;
    }
    else
    {
        bignum_dec_unsigned(n);
    }
}

#endif

static void bignum_add_unsigned(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");

    DTYPE_TMP tmp;
    int carry = 0;
    uint16_t maxlen = (a->len > b ->len) ? a->len : b->len;
    for (uint16_t i = 0; i < maxlen; ++i)
    {
        tmp = a->array[i] + b->array[i] + carry;
        carry = (tmp > MAX_VAL);
        c->array[i] = (tmp & MAX_VAL);
    }
    c->len = maxlen + (c->array[maxlen] != 0);
}


static void bignum_sub_unsigned(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");
    require (a->len >= b->len, "not implemented");

    if (len(a) < 1) return;

    DTYPE_TMP res;
    DTYPE_TMP tmp1;
    DTYPE_TMP tmp2;
    int borrow = 0;
    int i;
    for (i = 0; i < a->len; ++i)
    {
        tmp1 = (DTYPE_TMP)a->array[i] + (MAX_VAL + 1); /* + number_base */
        tmp2 = (DTYPE_TMP)b->array[i] + borrow;
        res = (tmp1 - tmp2);
        c->array[i] = (DTYPE)(res & MAX_VAL); /* "modulo number_base" == "% (number_base - 1)" if number_base is 2^N */
        borrow = (res <= MAX_VAL);
    }
    uint16_t j = a->len;
    while (j > 0)
    {
        --j;
        if (c->array[j] != 0)
            break;
    }
    if (c->array[j] != 0)
        c->len = j+1;
}


void bignum_add(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");

    if (a->negative == b->negative)
    {
        bignum_add_unsigned(a, b, c);
        c->negative = a->negative;
    }
    else
    {       
        int cmp = bignum_cmp_unsigned(a, b);
        if (cmp > 0)
        {
            bignum_sub_unsigned(a, b, c);
            c->negative = a->negative;
        }
        else if (cmp < 0)
        {
            bignum_sub_unsigned(b, a, c);
            c->negative = b->negative;
        }
        else
        {
            bignum_init(c);
        }
    }
}

void bignum_sub(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");

    if (a->negative != b->negative)
    {
        bignum_add_unsigned(a, b, c);
        c->negative = a->negative;
    }
    else
    {
        int cmp = bignum_cmp_unsigned(a, b);
        if (cmp > 0)
        {
            bignum_sub_unsigned(a, b, c);
            c->negative = a->negative;
        }
        else if (cmp < 0)
        {
            bignum_sub_unsigned(b, a, c);
            c->negative = !b->negative;
        }
        else
        {
            bignum_init(c);
        }
    }
}

static void bignum_mul_naive(const struct bn* a,
                            const struct bn* b,
                            struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");
    
    require (!(a->negative && b->negative), "not implemented");
    struct bn row;
    struct bn tmp;
    int i, j;

    bignum_init(c);

    for (i = 0; i < BN_ARRAY_SIZE; ++i)
    {
        bignum_init(&row);

        for (j = 0; j < BN_ARRAY_SIZE; ++j)
        {
            if (i + j < BN_ARRAY_SIZE)
            {
                bignum_init(&tmp);
                DTYPE_TMP intermediate = ((DTYPE_TMP)a->array[i] * (DTYPE_TMP)b->array[j]);
                bignum_from_int(&tmp, intermediate);
                _lshift_word(&tmp, i + j);
                bignum_add(&tmp, &row, &row);
            }
        }
        bignum_add(c, &row, c);
    }
}

inline static uint16_t bignum_len(const struct bn* n)
{
    require (n, "invalid parameter");
    return n->len;
    /*
    uint16_t i = BN_ARRAY_SIZE;
    for (;i--;) {
        if (n->array[i])
            return i+1;
    }
    */

    return 0;
}

static void bignum_shift_10(struct bn* n, uint16_t p)
{
    uint16_t l = bignum_len(n);
    if (l == 0) return;
    
    uint16_t i;
    for (i = l-1; i < p+l-1; ++i)
        n->array[i+p] = n->array[i];
    memset(n->array, 0, p);

}

static void bignum_split_at(const struct bn* a,
                            uint16_t k,
                            struct bn* lo,
                            struct bn* hi)
{
    uint16_t alen = bignum_len(a);
    uint16_t lo_len = (alen < k) ? alen : k;
    uint16_t i;
    for (i = 0; i < lo_len; ++i)
        lo->array[i] = a->array[i];
    for (; i < alen; ++i)
        hi->array[i-lo_len] = a->array[i];
}

#ifdef NAIVE_MUL
void (*bignum_mul)(const struct bn* a, const struct bn* b, struct bn* c) = bignum_mul_naive;
#else
void bignum_mul(const struct bn* a,
                const struct bn* b,
                struct bn* c)
{
    require (a && b, "invalid input");
    require (!(a->negative || b->negative), "not implemented");

    uint16_t alen = bignum_len(a), blen = bignum_len(b);
    if (alen <= 10 || blen <= 10) {
        bignum_mul_naive(a, b, c);
        return;
    }

    uint16_t m = (alen > blen) ? alen : blen;
    uint16_t m2 = m / 2;

    struct bn *pool = malloc(sizeof *pool * 9);
    struct bn   *lo1 = pool,
                *hi1 = pool+1,
                *lo2 = pool+2,
                *hi2 = pool+3,
                *z0 = pool+4,
                *z1 = pool+5,
                *z2 = pool+6,
                *t1 = pool+7,
                *t2 = pool+8;
           
    bignum_split_at(a, m2, lo1, hi1);
    bignum_split_at(b, m2 ,lo2, hi2);

    bignum_add(lo1, hi1, t1);
    bignum_add(lo2, hi2, t2);

    bignum_mul(lo1, lo2, z0);
    bignum_mul(t1, t2, z1);
    bignum_mul(hi1, hi2, z2);

    bignum_add(z0, z2, t1);
    bignum_sub(z1, t1, t2);

    bignum_shift_10(z2, 2*m2);
    bignum_shift_10(t2, m2);
    bignum_add(z0, z2, c);
    bignum_add(z0, t2, c);
}
#endif

void bignum_div(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");
    require (!(a->negative && b->negative), "not implemented");

    struct bn current;
    struct bn denom;
    struct bn tmp;

    bignum_from_int(&current, 1);               /*  int current = 1; */
    bignum_assign(&denom, b);                   /*  denom = b */
    bignum_assign(&tmp, a);                     /*  tmp   = a */

    const DTYPE_TMP half_max = 1 + (DTYPE_TMP)(MAX_VAL / 2);
    bool overflow = false;
    while (bignum_cmp(&denom, a) != LARGER)     /*  while (denom <= a) { */
    {
        if (denom.array[BN_ARRAY_SIZE - 1] >= half_max)
        {
            overflow = true;
            break;
        }
        _lshift_one_bit(&current);                /*    current <<= 1; */
        _lshift_one_bit(&denom);                  /*    denom <<= 1; */
    }
    if (!overflow)
    {
        _rshift_one_bit(&denom);                  /*  denom >>= 1; */
        _rshift_one_bit(&current);                /*  current >>= 1; */
    }
    bignum_init(c);                             /*  int answer = 0; */

    while (!bignum_is_zero(&current))           /*  while (current != 0) */
    {
        if (bignum_cmp(&tmp, &denom) != SMALLER)  /*    if (dividend >= denom) */
        {
            bignum_sub(&tmp, &denom, &tmp);         /*      dividend -= denom; */
            bignum_or(c, &current, c);              /*      answer |= current; */
        }
        _rshift_one_bit(&current);                /*    current >>= 1; */
        _rshift_one_bit(&denom);                  /*    denom >>= 1; */
    }                                           /*  return answer; */
}

#ifdef IMPLEMENT_ALL
void bignum_lshift(struct bn* a, struct bn* b, int nbits)
{
    require(a, "a is null");
    require(b, "b is null");
    require(nbits >= 0, "no negative shifts");

    if (bignum_is_zero(a))
    {
        bignum_init(b);
        return;
    }

    /* Handle shift in multiples of word-size */
    const int nbits_pr_word = (WORD_SIZE * 8);
    int nwords = nbits / nbits_pr_word;
    if (nwords != 0)
    {
        _lshift_word(a, nwords);
        nbits -= (nwords * nbits_pr_word);
    }

    if (nbits != 0)
    {
        int i;
        for (i = a->len; i > 0; --i)
        {
            a->array[i] = (a->array[i] << nbits) | (a->array[i - 1] >> ((8 * WORD_SIZE) - nbits));
        }
        a->array[i] <<= nbits;
        if (a->array[a->len] > 0)
            ++a->len;
    }
    bignum_assign(b, a);
}
#endif

void bignum_rshift(struct bn* a, struct bn* b, int nbits)
{
    require(a, "a is null");
    require(b, "b is null");
    require(nbits >= 0, "no negative shifts");

    if (a->len == 0)
    {
        bignum_init(b);
        return;
    }

    /* Handle shift in multiples of word-size */
    const int nbits_pr_word = (WORD_SIZE * 8);
    int nwords = nbits / nbits_pr_word;
    if (nwords != 0)
    {
        _rshift_word(a, nwords);
        nbits -= (nwords * nbits_pr_word);
    }

    if (nbits != 0)
    {
        int i;
        for (i = 0; i < a->len - 1; ++i)
        {
            a->array[i] = (a->array[i] >> nbits) | (a->array[i + 1] << ((8 * WORD_SIZE) - nbits));
        }
        a->array[i] >>= nbits;
        if (a->array[a->len-1] == 0)
            --a->len;
    }
    bignum_assign(b, a);
}


void bignum_mod(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");
    require (!(a->negative && b->negative), "not implemented");

    struct bn tmp;

    /* c = (a / b) */
    bignum_div(a, b, c);

    /* tmp = (c * b) */
    bignum_mul(c, b, &tmp);

    /* c = a - tmp */
    bignum_sub(a, &tmp, c);
}


#ifdef IMPLEMENT_ALL
void bignum_and(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");
    require (!(a->negative && b->negative), "not implemented");

    unit16_t maxlen = a->len > b->len ? a->len : b->len;
    int i;
    for (i = 0; i < maxlen; ++i)
    {
        c->array[i] = (a->array[i] & b->array[i]);
    }
    for ( --i; i > 0 && c->array[i] == 0; --i);
    c->len = (uint16_t)(i+1);
}

#endif

void bignum_or(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");
    require (!(a->negative && b->negative), "not implemented");

    uint16_t maxlen = a->len > b->len ? a->len : b->len;
    int i;
    for (i = 0; i < maxlen; ++i)
    {
        c->array[i] = (a->array[i] | b->array[i]);
    }
    c->len = maxlen;
}

#ifdef IMPLEMENT_ALL
void bignum_xor(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");
    require (!(a->negative && b->negative), "not implemented");

    uint16_t maxlen = a->len > b->len ? a->len : b->len;

    int i;
    for (i = 0; i < maxlen; ++i)
    {
        c->array[i] = (a->array[i] ^ b->array[i]);
    }
    for ( --i; i > 0 && c->array[i] == 0; --i);
    c->len = (uint16_t)(i+1);
}

#endif

static int bignum_cmp_unsigned(struct bn* a, struct bn* b)
{
    require(a, "a is null");
    require(b, "b is null");

    if (a->len > b->len) return LARGER;
    if (a->len < b->len) return SMALLER;

    int i = a->len;
    do
    {
        i -= 1; /* Decrement first, to start with last array element */
        if (a->array[i] > b->array[i])
        {
            return LARGER;
        }
        else if (a->array[i] < b->array[i])
        {
            return SMALLER;
        }
    }
    while (i != 0);

    return EQUAL;
}

int bignum_cmp(struct bn* a, struct bn* b)
{
    if (a->negative != b->negative)
    {
        if (a->negative) return -1;
        return 1;
    }

    int s = bignum_cmp_unsigned(a, b);
    if (a->negative) return -s;
    return s;
}

inline int bignum_is_zero(struct bn* n)
{
    require(n, "n is null");

    return (n->len == 0);
    /*
    for (uint32_t i = 0; i < BN_ARRAY_SIZE; ++i)
    {
        if (n->array[i]) return 0;
    }
    return 1;
    */
}

#ifdef IMPLEMENT_ALL
void bignum_pow(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");
    require (!(a->negative && b->negative), "not implemented");
    
    struct bn tmp;

    bignum_init(c);

    if (bignum_cmp(b, c) == EQUAL)
    {
        /* Return 1 when exponent is 0 -- n^0 = 1 */
        bignum_inc(c);
    }
    else
    {
        /* Copy a -> tmp */
        bignum_assign(&tmp, a);

        bignum_dec(b);

        /* Begin summing products: */
        while (!bignum_is_zero(b))
        {

            /* c = tmp * tmp */
            bignum_mul(&tmp, a, c);
            /* Decrement b by one */
            bignum_dec(b);

            bignum_assign(&tmp, c);
        }

        /* c = tmp */
        bignum_assign(c, &tmp);
    }
}
#endif

void bignum_assign(struct bn* dst, struct bn* src)
{
    require(dst, "dst is null");
    require(src, "src is null");

    memcpy(dst, src, BN_ARRAY_SIZE * WORD_SIZE);
    dst->negative = src->negative;
    dst->len = src->len;
}


#ifdef IMPLEMENT_ALL
/* Private / Static functions. */
static void _rshift_word(struct bn* a, int nwords)
{
    /* Naive method: */
    require(a, "a is null");
    require(nwords >= 0, "no negative shifts");

    uint16_t effective_nwords = a->len > nwords ? : nwords : a->len;
    for (uint16_t i = 0; i < effective_nwords; ++i)
        a->array[i] = a->array[i+1];
    a->len = effective_nwords;
    
    /*
    int i;
    for (i = 0; i < BN_ARRAY_SIZE - 1; ++i)
    {
        a->array[i] = a->array[i + 1];
    }

    for (; i < BN_ARRAY_SIZE; ++i)
    {
        a->array[i] = 0;
    }
    */
}
#endif

static void _lshift_word(struct bn* a, int nwords)
{
    require(a, "a is null");
    require(nwords >= 0, "no negative shifts");

    
    int32_t i;
    for ( i = a->len-1; i >= nwords; --i)
        a->array[i] = a->array[i-nwords];
    memset(a->array, 0, WORD_SIZE*(i+1));

    /*
    int i;
    for (i = (BN_ARRAY_SIZE - 1); i >= nwords; --i)
    {
        a->array[i] = a->array[i - nwords];
    }
    for (; i >= 0; --i)
    {
        a->array[i] = 0;
    }  
    */
}


static void _lshift_one_bit(struct bn* a)
{
    require(a, "a is null");

    if (bignum_is_zero(a)) return;

    int i;
    for (i = (int)a->len; i > 0; --i)
    {
        a->array[i] = (a->array[i] << 1) | (a->array[i - 1] >> ((8 * WORD_SIZE) - 1));
    }
    a->array[0] <<= 1;
    if (a->array[a->len] > 0)
        ++a->len;
}


static void _rshift_one_bit(struct bn* a)
{
    require(a, "a is null");

    if (bignum_is_zero(a)) return;

    int i;
    for (i = 0; i < a->len; ++i)
    {
        a->array[i] = (a->array[i] >> 1) | (a->array[i + 1] << ((8 * WORD_SIZE) - 1));
    }
    a->array[a->len - 1] >>= 1;
    if (a->array[a->len - 1] == 0)
        --a->len;
}


