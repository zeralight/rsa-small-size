#include <stdio.h>
#include <string.h>
#include "bn.h"

/* O(log n) */
void pow_mod(struct bn* a, struct bn* b, struct bn* n, struct bn* res)
{
  bignum_from_int(res, 1); /* r = 1 */

  struct bn tmpa;
  struct bn tmpb;
  struct bn tmp;
  bignum_assign(&tmpa, a);
  bignum_assign(&tmpb, b);

  while (1)
  {
    if (tmpb.array[0] & 1)     /* if (b % 2) */
    {
      bignum_mul(res, &tmpa, &tmp);  /*   r = r * a % m */
      bignum_mod(&tmp, n, res);
    }
    bignum_rshift(&tmpb, &tmp, 1); /* b /= 2 */
    bignum_assign(&tmpb, &tmp);

    if (bignum_is_zero(&tmpb))
      break;

    bignum_mul(&tmpa, &tmpa, &tmp);
    bignum_mod(&tmp, n, &tmpa);
  }
}

#ifdef RSA_MAIN
static void test_rsa1024(void)
{
  char public[]  = "a15f36fc7f8d188057fc51751962a5977118fa2ad4ced249c039ce36c8d1bd275273f1edd821892fa75680b1ae38749fff9268bf06b3c2af02bbdb52a0d05c2ae2384aa1002391c4b16b87caea8296cfd43757bb51373412e8fe5df2e56370505b692cf8d966e3f16bc62629874a0464a9710e4a0718637a68442e0eb1648ec5";
  char private[] = "3f5cc8956a6bf773e598604faf71097e265d5d55560c038c0bdb66ba222e20ac80f69fc6f93769cb795440e2037b8d67898d6e6d9b6f180169fc6348d5761ac9e81f6b8879529bc07c28dc92609eb8a4d15ac4ba3168a331403c689b1e82f62518c38601d58fd628fcb7009f139fb98e61ef7a23bee4e3d50af709638c24133d";
  char buf[8192];

  struct bn n; /* public  key */
  struct bn d; /* private key */
  struct bn e; /* public exponent */
  struct bn m; /* clear text message */
  struct bn c; /* cipher text */

  int x = 54321;

  bignum_init(&n);
  bignum_init(&d);
  bignum_init(&e);
  bignum_init(&m);
  bignum_init(&c);

  bignum_from_string(&n, public,  256);
  bignum_from_string(&d, private, 256);
  bignum_from_int(&e, 65537);
  bignum_init(&m);
  bignum_init(&c);

  bignum_from_int(&m, x);
  bignum_to_string(&m, buf, sizeof(buf));
  printf("m = %s \n", buf);


  printf("  Encrypting number x = %d \n", x);   fflush(stdout);
  pow_mod(&m, &e, &n, &c);
  printf("  Done...\n\n"); fflush(stdout);

  bignum_to_string(&c, buf, sizeof(buf));
  printf("  Decrypting cipher text '");
  printf("%s\n", buf); fflush(stdout);
  
  bignum_init(&m); 

  pow_mod(&c, &d, &n, &m);
  printf("  Done...\n\n"); fflush(stdout);


  bignum_to_string(&m, buf, sizeof(buf));
  printf("m = %s \n", buf);
}


static void test_rsa2048(void)
{
  char public[] = "f4f8fac0c1822f90c1ff35b817efa46256b70d77e12982653a375986e4512643de269599b2d10b660287bea5a73e768ae488a0d7d38abefecca5f65968be6acaa24453db4614bf7a185bbfd5730b5770944949288677701028ad644c234fff852b0c453651947be3a35a34a07d2736f83c9f126f50d77020cfc37f917995da89a9f561340661fcaf1a3324ac03adf960e242e648dfb9b7ca8bc7cdd18c75a00c202123a9032990859deee8de17457d5f71eb435b18276f82f7d65d6af966b9f33f93fd0714b8b311904daba68866b592762a47c6b7f6dc909a3123149b01b1c721fffa907b877784621ac8ec0aa3fe4f185636890a0fd327d8fde0a389adb4b1";
  char private[] = "40286523ce8a5602c78c1b79976b3fd63177c7a339e9312969d1cd34b2df3df2506032960a6b0d5d2e14772dd35b5c988bb9ecc619b520c882b884886e1250cdb929c3fc8da22973c4a562dc7840e429abec75a8936efc7e7ee8ca77d657c148133a27764e6f60f30179428735bfeb79a006d941261f0652d19715f5f7adf389cf36e879c2990e1da0ee67f218abbd5f42c82bbb696869dbc5a504465702c1c5d8b637930cebc80021ec25e048f59ee80aab5cb515a60d10ef01329b4cd543ed195b7e4af0d8f75e826b878f76392ce9afe4f935957536451f3dc4637235d831a669d986672ffd4c636d8d1cefedd72a3fdd20b084063e12a980a9068ff67b71";
  assert (sizeof public == 512 + 1);
  assert (sizeof private == 512 + 1);

  char buf[8192];

  struct bn n; /* public  key */
  struct bn d; /* private key */
  struct bn e; /* public exponent */
  struct bn m; /* clear text message */
  struct bn c; /* cipher text */

  //char x[] = "00f596037bc8379d63b80361316431393135353464373466356234326237653264653964326563613237356332370004282c3904282c3904282c3904282c3904282c93ae92f000000000000000002a7213cf7ea90010f596037bc800000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000481a988b8f1a988b8f1391e587f93b582cb297372cb93b282cb93b282cb93b282cb93b282cb93b282cb93b282c139192f000000000000000002a7213cf73a90010000000000000000000000000000000000000000000000000000001cdcdcdcdcd61323561663264333031";
  char x[] = "766160823de7b80154262f63649898d71ff506ef070101070157000a5606040a5407075b56010554303637313561643035373266646362633461653200ba2fe51810b24e7cec6f4c0c10e24e0c10e24e0c10e24e0c10e24e0c10e24e0c10e24ea6ba58920000000000000000aa5c18a445190010130504b40a858e376315490051aca1e22ecc608c00000000800000000000000000000000000000000000000000000000000000000000000000000000000000c02f8c41ed2f8c41ed26852fe5cc2f924e5f106f4c8c2fe24e8c2fe24e8c2fe24e8c2fe24e8c2fe24e8c2fe24e268558920000000000000000aa5c18a44b1873716c7574206c657320616d6973";

  //int x = 54321;

  bignum_init(&n);
  bignum_init(&d);
  bignum_init(&e);
  bignum_init(&m);
  bignum_init(&c);

  bignum_from_string(&n, public,  512);
  bignum_from_string(&d, private, 512);
  bignum_from_int(&e, 65537);
  bignum_init(&m);
  bignum_init(&c);

  //bignum_from_int(&m, x);
  bignum_from_string(&m, x, strlen(x));
  bignum_to_string(&m, buf, sizeof(buf));
  printf("m = %s \n", buf);

  printf(" Encrypting number x = %s\n", x);
  //printf("  Encrypting number x = %d \n", x);   fflush(stdout);
  pow_mod(&m, &e, &n, &c);
  printf("  Done...\n\n"); fflush(stdout);

  bignum_to_string(&c, buf, sizeof(buf));
  printf("%s\n", buf); fflush(stdout);

  bignum_init(&m); 

  pow_mod(&c, &d, &n, &m);
  printf("  Done...\n\n"); fflush(stdout);

  bignum_to_string(&m, buf, sizeof(buf));
  printf("m = %s \n", buf);
}

int main()
{
  //test_rsa1024();

  test_rsa2048();

  printf("\n");

  return 0;
}

#endif
