
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "bn.h"
#include "sha1.h"
#include "util.h"



struct karatsuba_ctx karatsuba_ctx;


/* Functions for shifting number in-place. */
static void _lshift_one_bit(struct bn* a);
static void _rshift_one_bit(struct bn* a);
static void _lshift_word(struct bn* a, int nwords);
static void _rshift_word(struct bn* a, int nwords);
#ifdef IMPLEMENT_ALL
static void bignum_dec_unsigned(struct bn* a);
static void bignum_inc_unsigned(struct bn* a);
#endif
void print_arr(const struct bn*);

/* Public / Exported functions. */
void bignum_init(struct bn* n)
{
    require(n, "n is null");

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

#if !defined(BIG_ENDIAN) || !defined(__H8_2329F__)
void bignum_to_bytes(const struct bn* n, unsigned char* bytes, uint32_t nbytes)
{
    require(n, "n is null");
    require(bytes, "str is null");
    require(nbytes > 0, "nbytes must be positive");

    memset(bytes, 0, nbytes);
    
    /*
    uint32_t i;
    for ( i = BN_ARRAY_SIZE; i-- && n->array[i] == 0;);
    */
    uint32_t i = n->len;
    uint32_t internal_len = i*WORD_SIZE;
    unsigned char* internal = heap_get(internal_len);
    uint32_t j = 0;
    for (; i--; ++j) {
        DTYPE d;
        i2osp(&d, n->array+i, WORD_SIZE);
        memcpy(internal+j*WORD_SIZE, &d, WORD_SIZE);
    }

    //require (nbytes <= internal_len, "not enough space");
    if (nbytes < internal_len)
        memcpy(bytes, internal + internal_len - nbytes, nbytes);
    else
        memcpy(bytes, internal, internal_len);
        
    heap_free(internal_len);
}
#endif

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

void bignum_add(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");

    DTYPE_TMP tmp;
    int carry = 0;
    uint16_t maxlen = (a->len > b->len) ? a->len : b->len;
    if (a->len < maxlen)
        memset(a->array+a->len, 0, WORD_SIZE*(maxlen - a->len));
    else if (b->len < maxlen)
        memset(b->array+b->len, 0, WORD_SIZE*(maxlen - b->len));
    for (uint16_t i = 0; i < maxlen; ++i)
    {
        tmp = ((DTYPE_TMP)a->array[i]) + b->array[i] + carry;
        carry = (tmp > MAX_VAL);
        c->array[i] = (tmp & MAX_VAL);
    }
    c->array[maxlen] = carry;
    c->len = maxlen + (carry != 0);

}


void bignum_sub(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");

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



void bignum_mul_naive(struct bn* a, struct bn* b, struct bn* c) {
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");
    

    struct bn row;
    struct bn tmp;
    int i, j;

    bignum_init(c);

    for (i = 0; i < a->len; ++i)
    {
        bignum_init(&row);

        for (j = 0; j < b->len; ++j)
        {
            bignum_init(&tmp);
            DTYPE_TMP intermediate = ((DTYPE_TMP)a->array[i] * (DTYPE_TMP)b->array[j]);
            bignum_from_int(&tmp, intermediate);
            _lshift_word(&tmp, i + j);
            bignum_add(&tmp, &row, &row);
        }
        bignum_add(c, &row, c);
    }
}

static void bignum_split_at(const struct bn* a,
                            uint16_t k,
                            struct bn* lo,
                            struct bn* hi)
{
    uint16_t alen = a->len;
    uint16_t lo_len = (alen < k) ? alen : k;
    uint16_t i;
    for (i = 0; i < lo_len; ++i)
        lo->array[i] = a->array[i];
    lo->len = lo_len;

    for (; i < alen; ++i)
        hi->array[i-lo_len] = a->array[i];
    hi->len = alen - lo_len;
}

void bignum_mul_karatsuba(struct bn* a, struct bn* b, struct bn* c) {
    uint16_t alen = a->len, blen = b->len;
    if (alen < 10 || blen < 10) {
        bignum_mul_naive(a, b, c);
        return;
    }

    uint16_t m = (alen > blen) ? alen : blen;
    uint16_t m2 = (m/2) + (m%2);
	
    struct bn *pool = karatsuba_ctx.pool + karatsuba_ctx.idx;
    karatsuba_ctx.idx += 9;

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
        
    // printf("a = "); print_arr(a);
    bignum_split_at(a, m2, x1, x0);

    bignum_split_at(b, m2 ,y1, y0); // b = y1* 2^(M2) + y0, = y1, y


    bignum_add(x1, x0, t1); // t1 = x0 + x1

    bignum_add(y1, y0, t2); // t2 = y0 + y1


    bignum_mul_karatsuba(x1, y1, z0);
    bignum_mul_karatsuba(t1, t2, z1);
    bignum_mul_karatsuba(x0, y0, z2);

    bignum_add(z0, z2, t1);
    require (bignum_cmp(z1, t1) != SMALLER, "632: exception");
    bignum_sub(z1, t1, t2);

    bignum_lshift(z2, z1, 2*m2*WORD_SIZE*8);
    bignum_lshift(t2, t1, m2*WORD_SIZE*8);
    bignum_add(z0, t1, z0);
    bignum_add(z0, z1, z0);
    bignum_assign(c, z0);

    karatsuba_ctx.idx -= 9;
}

void bignum_div(struct bn* a, struct bn* b, struct bn* c)
{
    require(a, "a is null");
    require(b, "b is null");
    require(c, "c is null");
    require (b->len > 0, "division by zero");
    
    struct bn *pool = heap_get(3 * sizeof(struct bn));
    struct bn *current = pool;
    struct bn *denom = pool+1;
    struct bn *tmp = pool+2;
    
    bignum_from_int(current, 1);               /*  int current = 1; */
    bignum_assign(denom, b);                   /*  denom = b */
    bignum_assign(tmp, a);                     /*  tmp   = a */
    
    while (bignum_cmp(denom, a) != LARGER)     /*  while (denom <= a) { */
    {
        require (!(denom->len == BN_ARRAY_SIZE && denom->array[BN_ARRAY_SIZE - 1] >= 1 + (DTYPE_TMP)(MAX_VAL / 2)), "division overflow");

        _lshift_one_bit(current);                /*    current <<= 1; */
        _lshift_one_bit(denom);                  /*    denom <<= 1; */
    }
    _rshift_one_bit(denom);                  
    _rshift_one_bit(current);                

    bignum_init(c);                             /*  int answer = 0; */

    while (!bignum_is_zero(current))           /*  while (current != 0) */
    {
        if (bignum_cmp(tmp, denom) != SMALLER)  /*    if (dividend >= denom) */
        {
            bignum_sub(tmp, denom, tmp);         /*      dividend -= denom; */
            bignum_or(c, current, c);              /*      answer |= current; */
        }
        _rshift_one_bit(current);
        _rshift_one_bit(denom);
    }                                            /*  return answer; */
    int16_t i;
    for (i = c->len-1; i >= 0 && c->array[i] == 0; --i);
    c->len = i+1;
    
    heap_free(3 * sizeof(struct bn));
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
            a->array[i] = (a->array[i] << nbits) | (a->array[i - 1] >> ((8 * WORD_SIZE) - nbits));
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

    struct bn *tmp = heap_get(sizeof *tmp);

    /* c = (a / b) */
    bignum_div(a, b, c);

    /* tmp = (c * b) */
    bignum_mul(c, b, tmp);
    /* c = a - tmp */
    bignum_sub(a, tmp, c);

    heap_free(sizeof *tmp);
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

int bignum_cmp(struct bn* a, struct bn* b)
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


/*
inline int bignum_is_zero(struct bn* n)
{
    require(n, "n is null");

    return (n->len == 0);
}
*/

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

    memcpy(dst, src, sizeof *dst);
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
    require (a->len-1 + nwords < BN_ARRAY_SIZE, "1094: overflow");
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
    
    
    DTYPE f = a->array[a->len-1];
    require (!(a->len == 256 && ((MAX_VAL >> 1) < f)), "this shouldn't not happen");

    for (int i = (int)a->len-1; i > 0; --i)
        a->array[i] = (a->array[i] << 1) | (a->array[i - 1] >> ((8 * WORD_SIZE) - 1));

    a->array[0] <<= 1;
    
    if (a->len < BN_ARRAY_SIZE) {
        a->array[a->len] = (f >> ((8 * WORD_SIZE) - 1));
        if (a->array[a->len] > 0)
            ++a->len;
    }
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

#if defined(USE_IO) || !defined(__H8_2329F__)
void print_arr(const struct bn* a)
{
    if (a->len == 0) {
        printf("%4x ", 0);
    } else {
    for (int i = 0; i < a->len; ++i)
        printf("%.4x ", a->array[i]);
    }
    printf("len = %d\n", a->len);
}
#endif
