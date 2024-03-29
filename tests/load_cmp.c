/*
  Testing bignum_from_string and bignum_from_int 

  Also testing bignum_cmp

*/

#ifdef BIGNUM_MAIN

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include "bn.h"
#include "util.h"


static void test_bignum_sign()
{
  struct bn x, y, z;

  bignum_from_int(&z, 1); // z = 1
  assert (z.array[0] == 1 && !z.negative);
  
  bignum_dec(&z); // z = 0
  assert (z.array[0] == 0&& !z.negative);

  bignum_dec(&z); // z = -1
  assert (z.array[0] == 1 && z.negative);

  bignum_dec(&z); // z = -2
  bignum_inc(&z); // z = -1
  assert (z.array[0] == 1 && z.negative);
  bignum_inc(&z); // z = 0
  assert (z.array[0] == 0 && !z.negative);
  bignum_inc(&z); // z = 1
  assert (z.array[0] == 1 && !z.negative);

  bignum_from_int(&x, 1); // x = 1
  bignum_from_int(&y, 1); // y = 1
  bignum_sub(&x, &y, &z); // z = 0
  assert (bignum_is_zero(&z) && !z.negative);

  bignum_from_int(&x, 2); // x = 2
  bignum_from_int(&y, 1); // y = 1
  bignum_sub(&x, &y, &z); // z = 1
  assert (z.array[0] == 1 && !z.negative);

  bignum_from_int(&x, 1); // x = 1
  bignum_from_int(&y, 2); // y = 2
  bignum_sub(&x, &y, &z); // z = -1
  assert (z.array[0] == 1 && z.negative);

  bignum_from_int(&x, 1); // x = 1
  bignum_dec(&x); // x = 0
  bignum_dec(&x); // x = -1
  bignum_from_int(&y, 2); // y = 2
  bignum_sub(&x, &y, &z); // z = -3
  assert (z.array[0] == 3 && z.negative);
  bignum_from_int(&y, 0); // y = 0
  bignum_sub(&x, &y, &z); // z = -1
  assert (z.array[0] == 1 && z.negative);

  bignum_from_int(&x, 0); // x = 0
  bignum_dec(&x); // x = -1
  bignum_from_int(&y, 0); // y = 0
  bignum_dec(&y); // y = -1
  bignum_sub(&x, &y, &z); // z = 0
  assert (bignum_is_zero(&z) && !z.negative);
  bignum_dec(&x); // x = -2
  bignum_sub(&x, &y, &z); // z = -1
  assert (z.array[0] == 1 && z.negative);
  bignum_dec(&y); // y = -2
  bignum_dec(&y); // y = -3
  bignum_sub(&x, &y, &z); // z = 1
  assert (z.array[0] == 1 && !z.negative);


  bignum_from_int(&x, 1); // x = 1
  bignum_from_int(&y, 1); // y = 1
  bignum_add(&x, &y, &z); // z = 2
  assert (z.array[0] == 2 && !z.negative);
  bignum_dec(&x); // x = 0
  bignum_dec(&x); // x = -1
  bignum_add(&x, &y, &z); // z = 0
  assert (bignum_is_zero(&z) && !z.negative);
  bignum_dec(&x); // x = -2
  bignum_add(&x, &y, &z); // z = -1
  assert (z.array[0] == 1 && z.negative);
  bignum_from_int(&y, 3); // y = 3
  bignum_add(&x, &y, &z); // z = -1
  assert (z.array[0] == 1 && !z.negative);
  bignum_from_int(&x, 2); // x = 1
  bignum_from_int(&y, 0); // y = 0
  bignum_dec(&y); // y = 0
  bignum_add(&x, &y, &z); // z = 
  assert (z.array[0] == 1 && !z.negative);
  bignum_dec(&y); // y = 1
  bignum_add(&x, &y, &z);
  assert (bignum_is_zero(&z) && !z.negative);
  bignum_dec(&y); // y = -2
  bignum_add(&x, &y, &z);
  assert (z.array[0] == 1 && z.negative);

  bignum_from_int(&x, 1);
  bignum_from_int(&y, 0);
  bignum_dec(&y);
  assert (bignum_cmp(&x, &y) > 0);
  bignum_dec(&x);
  assert (bignum_cmp(&x, &y) > 0);
  bignum_dec(&x);
  assert (bignum_cmp(&x, &y) == 0);
  bignum_dec(&x);
  assert (bignum_cmp(&x, &y) < 0);
  bignum_inc(&y);
  assert (bignum_cmp(&x, &y) < 0);

}

static void test_bignum_bytes()
{
  unsigned char bytes[] = "hello";
  struct bn n;
  bignum_init(&n);
  bignum_from_bytes(&n, bytes, sizeof bytes - 1);
  
  /*
  printf("Bignumber content: ");
  for (uint32_t i = 0; i < BN_ARRAY_SIZE; ++i)
    printf("%d ", n.array[i]);
  printf("\n");
  */

  unsigned char output[sizeof bytes - 1];
  bignum_to_bytes(&n, output, sizeof output);
  printf("bytes content: %.5s\n", output);

  assert (memcmp(bytes, output, sizeof bytes - 1) == 0);
}

char sabuf[8192];
char sbbuf[8192];
char scbuf[8192];
char sdbuf[8192];
char iabuf[8192];
char ibbuf[8192];
char icbuf[8192];
char idbuf[8192];
  
int main()
{
  test_bignum_bytes();
  test_bignum_sign();



  struct bn sa, sb, sc, sd, se;
  struct bn ia, ib, ic, id;

  bignum_init(&sa);
  bignum_init(&sb);
  bignum_init(&sc);
  bignum_init(&sd);
  bignum_init(&ia);
  bignum_init(&ib);
  bignum_init(&ic);
  bignum_init(&id);

  printf("\nLoading numbers from strings and from int.\n");
  
  bignum_from_string(&sa, "000000FF", 8);
  bignum_from_string(&sb, "0000FF00", 8);
  bignum_from_string(&sc, "00FF0000", 8);
  bignum_from_string(&sd, "FF000000", 8);
 
  bignum_from_int(&ia, 0x000000FF);
  bignum_from_int(&ib, 0x0000FF00);
  bignum_from_int(&ic, 0x00FF0000);
  bignum_from_int(&id, 0xFF000000);

  printf("Verifying comparison function.\n");

  assert(bignum_cmp(&ia, &ib) == SMALLER);
  assert(bignum_cmp(&ia, &ic) == SMALLER);
  assert(bignum_cmp(&ia, &id) == SMALLER);

  assert(bignum_cmp(&ib, &ia) == LARGER);
  assert(bignum_cmp(&ic, &ia) == LARGER);
  assert(bignum_cmp(&id, &ia) == LARGER);

  assert(bignum_cmp(&sa, &sb) == SMALLER);
  assert(bignum_cmp(&sa, &sc) == SMALLER);
  assert(bignum_cmp(&sa, &sd) == SMALLER);

  assert(bignum_cmp(&sb, &sa) == LARGER);
  assert(bignum_cmp(&sc, &sa) == LARGER);
  assert(bignum_cmp(&sd, &sa) == LARGER);

  assert(bignum_cmp(&ia, &sa) == EQUAL);
  assert(bignum_cmp(&ib, &sb) == EQUAL);
  assert(bignum_cmp(&ic, &sc) == EQUAL);
  assert(bignum_cmp(&id, &sd) == EQUAL);

  printf("Verifying to_string function.\n");

  bignum_to_string(&sa, sabuf, sizeof(sabuf));
  bignum_to_string(&sb, sbbuf, sizeof(sbbuf));
  bignum_to_string(&sc, scbuf, sizeof(scbuf));
  bignum_to_string(&sd, sdbuf, sizeof(sdbuf));

  bignum_to_string(&ia, iabuf, sizeof(iabuf));
  bignum_to_string(&ib, ibbuf, sizeof(ibbuf));
  bignum_to_string(&ic, icbuf, sizeof(icbuf));
  bignum_to_string(&id, idbuf, sizeof(idbuf));

  assert(strcmp(sabuf, iabuf) == 0);
  assert(strcmp(sbbuf, ibbuf) == 0);
  assert(strcmp(scbuf, icbuf) == 0);
  assert(strcmp(sdbuf, idbuf) == 0);

  printf("Verifying increment + decrement functions.\n");

  bignum_init(&sd);
  int i;
  for (i = 0; i < 255; ++i)
  {
    bignum_inc(&sd);
    assert(!bignum_is_zero(&sd));
  }

  assert(bignum_cmp(&sd, &ia) == EQUAL);

  for (i = 0; i < 255; ++i)
  {
    assert(!bignum_is_zero(&sd));
    bignum_dec(&sd);
  }
  assert(bignum_is_zero(&sd));

  bignum_init(&sa);
  bignum_init(&sb);
  bignum_init(&sc);
  bignum_init(&sd);

  char hex_1000[]    = "000003E8";
  char hex_1000000[] = "000F4240";

  /* Load 0x0308 into A and B from string */
  bignum_from_string(&sa, hex_1000, 8);
  bignum_from_string(&sb, hex_1000, 8);

  /* Load 0x0308 into C from integer */
  bignum_from_int(&sc, 0x3e8);

  /* Check for agreement - does bignum_from_string match bignum_from_int? */
  assert(bignum_cmp(&sa, &sc) == EQUAL);
  assert(bignum_cmp(&sb, &sc) == EQUAL);

  /* Load comparison value: */
  bignum_from_string(&sd, hex_1000000, 8);
  bignum_from_int(&se, 0xf4240);

  /* Perform calculation:  C = A * B => C = 0x308 * 0x308 */
  bignum_mul(&sa, &sb, &sc);

  /* Check if results agree: */
  assert(bignum_cmp(&sc, &sd) == EQUAL);
  assert(bignum_cmp(&sc, &se) == EQUAL);

  /* Perform calculation other way around: C = B * A */
  bignum_mul(&sb, &sa, &sc);

  /* Check if results agree: */
  assert(bignum_cmp(&sc, &sd) == EQUAL);
  assert(bignum_cmp(&sc, &se) == EQUAL);


  printf("\nTests successful.\n\n");

  return 0;
}
#endif
