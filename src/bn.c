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
#ifdef IMPLEMENT_ALL
static void bignum_dec_unsigned(struct bn* a);
static void bignum_inc_unsigned(struct bn* a);
#endif
static int bignum_cmp_unsigned(struct bn* a, struct bn* b);
static uint16_t bignum_len(const struct bn* a);
void print_arr(const struct bn*);

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
    if (n->array[0]) n->len = 1;
    n->array[1] = (i & 0xffff0000) >> 16;
    if (n->array[1]) n->len = 2;
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
        ret += ((int32_t)n->array[1]) << 16;
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
    for (n->len = j; n->len > 0 && n->array[n->len-1] == 0; --n->len);
}


void bignum_to_string(struct bn* n, char* str, int nbytes)
{
    require(n, "n is null");
    require(str, "str is null");
    require(nbytes > 0, "nbytes must be positive");
    require((nbytes & 1) == 0, "string format must be in hex -> equal number of bytes");
    require (!n->negative, "only unsigned numbers can be converted to string");

    if (n->len == 0)
    {
        memset(str, 0, nbytes);
        *str = '0';
        return;
    }

    int j = n->len - 1;
    int i = 0;

    while ((j >= 0) && (nbytes > (i + 1)))
    {
        sprintf(&str[i], SPRINTF_FORMAT_STR, n->array[j]);
        i += (2 * WORD_SIZE);
        j -= 1;
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
    if (i == n->len-1)
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
        bignum_inc_unsigned(n);
    else
        bignum_dec_unsigned(n);
}

#endif

static void bignum_add_unsigned(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");

    /*
    printf("bignum_add_unsigned:\n");
    printf("a: "); print_arr(a);
    printf("b: "); print_arr(b);
    */

    DTYPE_TMP tmp;
    int carry = 0;
    uint16_t maxlen = (a->len > b->len) ? a->len : b->len;
    if (a->len < maxlen)
        memset(a->array+a->len, 0, WORD_SIZE*(maxlen - a->len));
    else if (b->len < maxlen)
        memset(b->array+b->len, 0, WORD_SIZE*(maxlen - b->len));
    for (uint16_t i = 0; i < maxlen; ++i)
    {
        // printf("a[%d] = %d | b[%d] = %d\n", i, a->array[i], i, b->array[i]);
        tmp = ((DTYPE_TMP)a->array[i]) + b->array[i] + carry;
        // printf("tmp = %d\n", tmp);
        carry = (tmp > MAX_VAL);
        // printf("carry = %d\n", carry);
        c->array[i] = (tmp & MAX_VAL);
    }
    c->array[maxlen] = carry;
    c->len = maxlen + (carry != 0);

    // printf("c: "); print_arr(c);

}


static void bignum_sub_unsigned(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");
    require (bignum_cmp_unsigned(a, b) != SMALLER, "not implemented");

    if (a->len < 1)
    {
        bignum_init(c);
        return;
    }
    memset(b->array+b->len, 0, WORD_SIZE*(a->len-b->len));
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

    /*
    printf("bignum_add:\n");
    printf("a = ");
    for (int i = 0; i < a->len; ++i)
        printf("%4x ", a->array[i]);
    printf("len = %d | negative = %d\n", a->len, a->negative);
    printf("\nb = ");
    for (int i = 0; i < b->len; ++i)
        printf("%4x ", b->array[i]);
    printf("len = %d | negative = %d\n", b->len, b->negative);
    */
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
    /*
    printf("bignum_add: c = ");
    for (int i = 0; i < c->len; ++i)
        printf("%4x ", c->array[i]);
    printf("len = %d | negative = %d\n", c->len, c->negative);
    */
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

void bignum_mul_naive(struct bn* a,
                        struct bn* b,
                        struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");
    
    /*
    printf("bignum_mul_naive:\n");
    printf("a: "); print_arr(a);
    printf("b: "); print_arr(b);
    */
    struct bn row;
    struct bn tmp;
    int i, j;

    bool asign = a->negative;
    bool bsign = b->negative;
    if (asign != bsign)
    {
        printf("Detected negaitve multiplication\n");
        fflush(stdout);
    }
    a->negative = b->negative = false;
    bignum_init(c);

    for (i = 0; i < a->len; ++i)
    {
        bignum_init(&row);

        for (j = 0; j < b->len; ++j)
        {
            bignum_init(&tmp);
            // printf("i = %d | a[i] = %d | j = %d | b[j] = %d\n", i, a->array[i], j, b->array[j]);
            DTYPE_TMP intermediate = ((DTYPE_TMP)a->array[i] * (DTYPE_TMP)b->array[j]);
            // printf("intermediate = %d\n", intermediate);
            bignum_from_int(&tmp, intermediate);
            _lshift_word(&tmp, i + j);
            bignum_add(&tmp, &row, &row);
        }
        bignum_add(c, &row, c);

    }
    c->negative = asign != bsign;
    a->negative = asign;
    b->negative = bsign;
     // printf ("bignum_mul_naive end:\nc: "); print_arr(c);
}

inline static uint16_t bignum_len(const struct bn* n)
{
    require (n, "invalid parameter");
    return n->len;

    return 0;
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
    lo->len = lo_len;
    lo->negative = false;

    for (; i < alen; ++i)
        hi->array[i-lo_len] = a->array[i];
    hi->len = alen - lo_len;
    hi->negative = false;
}

void bignum_mul(struct bn* a,
                struct bn* b,
                struct bn* c)
{
    require (a && b, "invalid input");
    require (!(a->negative || b->negative), "not implemented");
    struct bn bb, ba;
    bignum_assign(&bb, b);
    bignum_assign(&ba, a);
    a = &ba;
    b = &bb;
#ifdef NAIVE_MUL
    bignum_mul_naive(a, b, c);
#else
    bignum_mul_karatsuba(a, b, c);
#endif
}
void bignum_mul_karatsuba(struct bn* a,
                        struct bn* b,
                        struct bn* c)
{
    
    uint16_t alen = bignum_len(a), blen = bignum_len(b);
    if (alen <= 10 || blen <= 10) {
        bignum_mul_naive(a, b, c);
        return;
    }

    uint16_t m = (alen > blen) ? alen : blen;
    uint16_t m2 = (m/2) + (m%2);

    struct bn *pool = malloc(sizeof *pool * 9);
    struct bn   *x1 = pool,
                *x0 = pool+1,
                *y1 = pool+2,
                *y0 = pool+3,
                *z0 = pool+4,
                *z1 = pool+5,
                *z2 = pool+6,
                *t1 = pool+7,
                *t2 = pool+8;

    for (uint8_t i = 0; i < 9; ++i)
        bignum_init(pool+i);
    
    struct bn another_c;
    bignum_mul_naive(a, b, &another_c);

    // printf("a = "); print_arr(a);
    bignum_split_at(a, m2, x1, x0);

    bignum_split_at(b, m2 ,y1, y0); // b = y1* 2^(M2) + y0, = y1, y


    bignum_add(x1, x0, t1); // t1 = x0 + x1

    bignum_add(y1, y0, t2); // t2 = y0 + y1


    bignum_mul_karatsuba(x1, y1, z0);
    bignum_mul_karatsuba(t1, t2, z1);
    bignum_mul_karatsuba(x0, y0, z2);

    bignum_add(z0, z2, t1);
    assert (bignum_cmp(z1, z2) != SMALLER);
    bignum_sub(z1, t1, t2);

    bignum_lshift(z2, z1, 2*m2*WORD_SIZE*8);
    bignum_lshift(t2, t1, m2*WORD_SIZE*8);
    bignum_add(z0, t1, z0);
    bignum_add(z0, z1, z0);
    bignum_assign(c, z0);

    free(pool);
}

void bignum_div(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");
    require (!(a->negative && b->negative), "not implemented");
    require (b->len > 0, "division by zero");

    struct bn current;
    struct bn denom;
    struct bn tmp;

    bignum_from_int(&current, 1);               /*  int current = 1; */
    bignum_assign(&denom, b);                   /*  denom = b */
    bignum_assign(&tmp, a);                     /*  tmp   = a */

    /*
    printf("bignum_div: \n");
    printf("a: "); print_arr(a);
    printf("b: "); print_arr(b);
    */

    const DTYPE_TMP half_max = 1 + (DTYPE_TMP)(MAX_VAL / 2);
    bool overflow = false;
    
    while (bignum_cmp(&denom, a) != LARGER)     /*  while (denom <= a) { */
    {
        /*
        printf("bignum_div: \n");
        printf("denom: "); print_arr(&denom);
        printf("a: "); print_arr(a);
        */
        if (denom.len == BN_ARRAY_SIZE && denom.array[BN_ARRAY_SIZE - 1] >= half_max)
        {
            overflow = true;
            break;
        }
        // printf("    current before Lshift: "); print_arr(&current);
        _lshift_one_bit(&current);                /*    current <<= 1; */
        // printf("    current after Lshift: "); print_arr(&current);
        // printf("    denom before Lshift: "); print_arr(&denom);
        _lshift_one_bit(&denom);                  /*    denom <<= 1; */
        // printf("    denom after Lshift: "); print_arr(&denom);
    }

    
    if (!overflow)
    {
        // printf("denom before Rshift: "); print_arr(&denom);
        _rshift_one_bit(&denom);                  
        // printf("denom After Rshift: "); print_arr(&denom);
        // printf("current before Rshift: "); print_arr(&current);
        _rshift_one_bit(&current);                
        // printf("current AFTER Rshift: "); print_arr(&current);
    }
    bignum_init(c);                             /*  int answer = 0; */

    while (!bignum_is_zero(&current))           /*  while (current != 0) */
    {
        // printf("    while bignum_is_zero(&current):\n");
        if (bignum_cmp(&tmp, &denom) != SMALLER)  /*    if (dividend >= denom) */
        {
            /*
            printf("        bignum_cmp before sub:\n");
            
            printf("        tmp: "); print_arr(&tmp);
            printf("        denom: "); print_arr(&denom);
            */
            bignum_sub(&tmp, &denom, &tmp);         /*      dividend -= denom; */
            /*
            printf("        after sub\n");
            printf("        tmp: "); print_arr(&tmp);
            printf("        before or:\n");
            printf("        c: "); print_arr(c);
            printf("        current: "); print_arr(&current);
            */
            bignum_or(c, &current, c);              /*      answer |= current; */
            /*
            printf("        after or\n");
            printf("        c: "); print_arr(c);
            */
        }
        /*
        printf("    before Rshift:\n");
        printf("    current: "); print_arr(&current);
        printf("    denom: "); print_arr(&denom);
        */
        _rshift_one_bit(&current);
        _rshift_one_bit(&denom);
        /*
        printf("    after Rshift:\n");
        printf("    current: "); print_arr(&current);
        printf("    denom: "); print_arr(&denom);
        */
    }                                           /*  return answer; */
    int16_t i;
    for (i = c->len-1; i >= 0 && c->array[i] == 0; --i);
    c->len = i+1;
    /*
    printf("bignum_div: end:\n");
    printf("c = "); print_arr(c);
    */
}

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
        a->array[a->len] = 0;
        for (int16_t i = a->len; i > 0; --i)
        {
            a->array[i] = (a->array[i] << nbits) | (a->array[i - 1] >> ((8 * WORD_SIZE) - nbits));
            if(a->array[a->len] > 0) {
                printf("ggggg\n");
            }
        }
        a->array[0] <<= nbits;
        if (a->array[a->len] > 0)
            ++a->len;
    }
    bignum_assign(b, a);
}

void bignum_rshift(struct bn* a, struct bn* b, int nbits)
{
    require(a, "a is null");
    require(b, "b is null");
    require(nbits >= 0, "no negative shifts");

    struct bn ba;
    bignum_assign(&ba, a);
    a = &ba;
    
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

    struct bn bb;
    struct bn ba;
    bignum_assign(&bb, b);
    bignum_assign(&ba, a);

    a = &ba;
    b = &bb;

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

    struct bn *max, *min;
    if (a->len > b->len)
    {
        max = a;
        min = b;
    }
    else
    {
        max = b;
        min = a;
    }
    if (max->len == 0)
    {
        bignum_init(c);
        return;
    }
    for (int i = 0; i < min->len; ++i)
        c->array[i] = (max->array[i] & min->array[i]);
    if (min->len < max->len)
        memset(c+min->len, 0, (max->len-min->len)*WORD_SIZE);
    int16_t i;
    for (i = min->len-1; i >= 0 && c->array[i] == 0; --i);
    c->len = i+1;

    // printf("bignum_and: c = "); print_arr(c);
}

#endif

void bignum_or(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");
    require (!(a->negative && b->negative), "not implemented");

    struct bn *max, *min;
    if (a->len > b->len)
    {
        max = a;
        min = b;
    }
    else
    {
        max = b;
        min = a;
    }
    if (max->len == 0)
    {
        bignum_init(c);
        return;
    }
    for (int i = 0; i < min->len; ++i)
        c->array[i] = (max->array[i] | min->array[i]);
    for (int i = min->len; i < max->len; ++i)
        c->array[i] = max->array[i];
    c->len = max->len;
}

#ifdef IMPLEMENT_ALL
void bignum_xor(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");
    require (!(a->negative && b->negative), "not implemented");

    struct bn *max, *min;
    if (a->len > b->len)
    {
        max = a;
        min = b;
    }
    else
    {
        max = b;
        min = a;
    }
    if (max->len == 0)
    {
        bignum_init(c);
        return;
    }

    for (int16_t i = 0; i < min->len; ++i)
        c->array[i] = (max->array[i] ^ min->array[i]);
    
    if (min->len < max->len)
    {
        for (int16_t i = min->len; i < max->len; ++i)
            c->array[i] = max->array[i];
    }
    int16_t i;
    for (i = max->len-1; i >= 0 && c->array[i] == 0; --i);
    c->len = i+1;
}

#endif

static int bignum_cmp_unsigned(struct bn* a, struct bn* b)
{
    require(a, "a is null");
    require(b, "b is null");

    if (a->len > b->len) return LARGER;
    if (a->len < b->len) return SMALLER;
    if (bignum_is_zero(a)) return EQUAL;
    for (uint16_t i = a->len; i--;)
    {
      if (a->array[i] > b->array[i]) return LARGER;
      if (a->array[i] < b->array[i]) return SMALLER;
    }
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
}

#ifdef IMPLEMENT_ALL
void bignum_pow(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");
    require (!(a->negative && b->negative), "not implemented");
    
    struct bn tmp;

    /*
    printf("bignum_pow:\n");
    printf("a: "); print_arr(a);
    printf("b: "); print_arr(b);
    */

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

        // printf("b before dec "); print_arr(b);
        bignum_dec(b);
        // printf("b after dec "); print_arr(b);

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

void bignum_assign(struct bn* dst, const struct bn* src)
{
    require(dst, "dst is null");
    require(src, "src is null");

    memcpy(dst, src, BN_ARRAY_SIZE * WORD_SIZE);
    dst->negative = src->negative;
    dst->len = src->len;
}


/* Private / Static functions. */
static void _rshift_word(struct bn* a, int nwords)
{
    /* Naive method: */
    require(a, "a is null");
    require(nwords >= 0, "no negative shifts");

    
    
    uint16_t effective_nwords = a->len > nwords ? nwords : a->len;
    for (uint16_t i = 0; i < effective_nwords; ++i)
        a->array[i] = a->array[i+nwords];
    
    for (a->len = effective_nwords; a->len > 0 && a->array[a->len-1] == 0; --a->len);

}

static void _lshift_word(struct bn* a, int nwords)
{
    require(a, "a is null");
    require(nwords >= 0, "no negative shifts");

    /*
    if (a->len > 0 && nwords > 0) {
    printf("_lshift_word:\n");
    printf("a: ");
    print_arr(a);
    printf("nwords = %d\n", nwords);
    }
    */

    if (a->len == 0 || nwords == 0)
    {
        // printf("no shifting.\n");
        return;
    }

    int32_t i;
    assert (a->len-1 + nwords < BN_ARRAY_SIZE);
    for ( i = a->len-1; i >= 0; --i)
        a->array[i+nwords] = a->array[i];
    memset(a->array, 0, WORD_SIZE*nwords);
    for (a->len += nwords; a->len > 0 && a->array[a->len-1] == 0; --a->len);

    // printf("result: "); print_arr(a);

}


static void _lshift_one_bit(struct bn* a)
{
    require(a, "a is null");

    if (bignum_is_zero(a)) return;

    a->array[a->len] = 0;
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
    for (i = 0; i+1 < a->len; ++i)
    {
        a->array[i] = (a->array[i] >> 1) | (a->array[i + 1] << ((8 * WORD_SIZE) - 1));
    }
    a->array[a->len - 1] >>= 1;
    if (a->array[a->len - 1] == 0)
        --a->len;
}

#ifdef IMPLEMENT_ALL
void print_arr(const struct bn* a)
{
    if (a->len == 0) {
        printf("%4x ", 0);
    } else {
    for (int i = 0; i < a->len; ++i)
        printf("%.4x ", a->array[i]);
    }
    printf("len = %d | negative = %d\n", a->len, a->negative);
}
#endif
