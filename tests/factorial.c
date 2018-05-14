#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "bn.h"
#include "util.h"

#ifdef PROFILER
#include <time.h>
#endif

void factorial(struct bn* n, struct bn* res)
{
  struct bn tmp;

  /* Copy n -> tmp */
  bignum_assign(&tmp, n);

  /* Decrement n by one */
  bignum_dec(n);
  
  /* Begin summing products: */
  while (!bignum_is_zero(n))
  {
#ifdef MUL_NAIVE
    /* res = tmp * n */
    bignum_mul_naive(&tmp, n, res);
#else
	bignum_mul_karatsuba(&tmp, n, res);
#endif	
    /* n -= 1 */
    bignum_dec(n);
    
    /* tmp = res */
    bignum_assign(&tmp, res);
  }

  /* res = tmp */
  bignum_assign(res, &tmp);
}


#ifdef FACTORIAL_MAIN
int main()
{

    struct bn num;
    struct bn result;
	
	
	//unsigned char expected_hex[] = "1b30964ec395dc24069528d54bbda40d16e966ef9a70eb21b5b2943a321cdf10391745570cca9420c6ecb3b72ed2ee8b02ea2735c61a000000000000000000000000";
    unsigned char expected_hex[] = "026ca8439285c67e3b9e32731120f78b66f85612a4dd1df6c1d2c69a2d7685f85e75b82bf36e22dcb6ca5044f43fef0b3316049241c821e1ec1c63f95685931f87152ced4befc5ddf7b76719a636f68e7054bf28b57d54d40975ab14d65900681c49044d1725031edbf3c1c5c595b871d6864c371b0cc54ef19d42ad02833bcaf5fb1671b523a143b132c7e1971f7bf5ca77505c960f14b330e6c90dc2539431329ef78a1e9f26b2ead7d28a622e6b586bcee22bd0a495442c6a1235588988252cbd4d36975560fb8e7e5c8cf06f29aeb68659c5cb4cf8d011375b00000000000000000000000000000000000000000000000000000000000000000000000000";
    int n = 300;

    uint16_t len = (sizeof expected_hex - 1) / 2;
    unsigned char expected[8192];
    unhexlify(expected_hex, 2*len, expected);
	
    
#define MUL_NAIVE	
	bignum_from_int(&num, n);
	factorial(&num, &result);
    unsigned char buf[8192];
    memset(buf, 0, 8192);
    bignum_to_bytes(&result, buf, sizeof buf);
    printf("factorial(100) using bignum = "); print_hex(buf, len);
    require (memcmp(expected, buf, len) == 0, "wrong result");
    printf("Naive Multiplication OK\n");
	
#undef MUL_NAIVE	
	bignum_from_int(&num, n);
	factorial(&num, &result);
	memset(buf, 0, 8192);
    bignum_to_bytes(&result, buf, sizeof buf);
    require (memcmp(expected, buf, len) == 0, "wrong result");
    printf("Karatsuba Multiplication OK\n");
	

    printf("measuring performance:\n");

    clock_t start, end;
    double cpu_time_used;
#define NAIVE_MUL
    bignum_from_int(&num, n);
    start = clock();
    factorial(&num, &result);
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Naive multiplication duration: %lf\n", cpu_time_used);

#undef NAIVE_MUL
    bignum_from_int(&num, n);
    start = clock();
    factorial(&num, &result);
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Karatsuba multiplication duration: %lf\n", cpu_time_used);


    struct bn num2;
    printf("Simple multiplication:\n");
    char n1[] = "266469bcf5afc5d96b329b68782a3bca40dbb91467566a0e35ff6a4ed4f4640819acde91bfb82c3e37b488803366bdf217e1efe4b6a2fbddef2289aaec62ae576e174a271c41000000000000000000000000000000000000000000000000000000000000";
    char n2[] = "59638eade54811fc3a1f1074f7a888090df07618254bcba89ac79d9093da550cd136c776d8d5d2aac7c41c291ebf95694a2ca67b01aefe0aab9757f89b4a20a8ed55d1affb805ff4e400000000000000000000000000000000000000000000000000000000000000";
    bignum_from_string(&num, n1, sizeof n1 - 1);
    bignum_from_string(&num2, n2, sizeof n2 - 1);
    
#define NAIVE_MUL
    start = clock();
    bignum_mul(&num, &num2, &result);
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Naive multiplication duration: %lf\n", cpu_time_used);

#undef NAIVE_MUL
    start = clock();
    bignum_mul(&num, &num2, &result);
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Karatsuba multiplication duration: %lf\n", cpu_time_used);


    printf("done.\n");
    return 0;
}
#endif

