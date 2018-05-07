/*
  message m = 123

  P = 61                  <-- 1st prime, keep secret and destroy after generating E and D
  Q = 53                  <-- 2nd prime, keep secret and destroy after generating E and D
  N = P * Q = 3233        <-- modulo factor, give to others

  T = totient(N)          <-- used for key generation
    = (P - 1) * (Q - 1)
    = 3120

  E = 1 < E < totient(N)  <-- public exponent, give to others
  E is chosen to be 17

  find a number D such that ((E * D) / T) % T == 1
  D is chosen to be 2753  <-- private exponent, keep secret


  encrypt(T) = (T ^ E) mod N     where T is the clear-text message
  decrypt(C) = (C ^ D) mod N     where C is the encrypted cipher


  Public key consists of  (N, E)
  Private key consists of (N, D)


  RSA wikipedia example (with small-ish factors):

    public key  : n = 3233, e = 17
    private key : n = 3233, d = 2753
    message     : n = 123

    cipher = (123 ^ 17)   % 3233 = 855
    clear  = (855 ^ 2753) % 3233 = 123  

*/


#include <stdio.h>
#include <string.h> /* for memcpy */
#include "../bn.h"

struct bn M, C, E, D, N;
struct bn tmpa;
struct bn tmpb;
struct bn tmp;
/* O(log n) */
void pow_mod_faster(struct bn* a, struct bn* b, struct bn* n, struct bn* res)
{
  
  bignum_from_int(res, 1); /* r = 1 */

  bignum_assign(&tmpa, a);
  bignum_assign(&tmpb, b);

  while (1)
  {
    printf("Step done..\n");
    if (tmpb.array[0] & 1)     /* if (b % 2) */
    {
      printf("Mul\n");
      bignum_mul(res, &tmpa, &tmp);  /*   r = r * a % m */
      printf("Mod\n");
      bignum_mod(&tmp, n, res);
    }
    printf("R shift\n");
    bignum_rshift(&tmpb, &tmp, 1); /* b /= 2 */
    printf("Assign\n");
    bignum_assign(&tmpb, &tmp);
    printf("BigNum Zero\n");
    if (bignum_is_zero(&tmpb))
      break;

    printf("Mul\n");
    bignum_mul(&tmpa, &tmpa, &tmp);
    printf("Mod\n");
    bignum_mod(&tmp, n, &tmpa);
  }
}

static void test_rsa_1(void)
{
  /* Testing with very small and simple terms */
  char buf[8192];


  const int p = 11;
  const int q = 13;
  const int n = p * q;
//int t = (p - 1) * (q - 1);
  const int e = 7;
  const int d = 103;
  const int m = 9;
  const int c = 48;
  int m_result, c_result;

  bignum_init(&M);
  bignum_init(&C);
  bignum_init(&D);
  bignum_init(&E);
  bignum_init(&N);

  bignum_from_int(&D, d);
  bignum_from_int(&C, 48);
  bignum_from_int(&N, n);

  printf("\n");

  printf("  Encrypting message m = %d \n", m);
  printf("  %d ^ %d mod %d = %d ? \n", m, e, n, c);
  bignum_from_int(&M, m);
  bignum_from_int(&E, e);
  bignum_from_int(&N, n);
  printf("Initing all\n");
  pow_mod_faster(&M, &E, &N, &C);
  printf("Powering over\n");
  c_result = bignum_to_int(&C);
  bignum_to_string(&C, buf, sizeof(buf));
  printf("  %d ^ %d mod %d = %d \n", m, e, n, c_result);
  printf("  %d ^ %d mod %d = %s \n", m, e, n, buf);

  printf("\n");

  printf("  Decrypting message c = %d \n", c);
  printf("  %d ^ %d mod %d = %d ? \n", c, d, n, m);
  pow_mod_faster(&C, &D, &N, &M);
  m_result = bignum_to_int(&M);
  bignum_to_string(&M, buf, sizeof(buf));
  printf("  %d ^ %d mod %d = %d \n", c, d, n, m_result);
  printf("  %d ^ %d mod %d = %s \n", c, d, n, buf);

  printf("\n");
}





void test_rsa_2(void)
{
  char buf[8192];


  const int p = 61;
  const int q = 53;
  const int n = p * q;
//int t = (p - 1) * (q - 1);
  const int e = 17;
  const int d = 2753;
  const int m = 123;
  const int c = 855;
  int m_result, c_result;

  bignum_init(&M);
  bignum_init(&C);
  bignum_init(&D);
  bignum_init(&E);
  bignum_init(&N);

  bignum_from_int(&D, d);
  bignum_from_int(&C, 1892);
  bignum_from_int(&N, n);

  printf("\n");

  printf("  Encrypting message m = %d \n", m);
  printf("  %d ^ %d mod %d = %d ? \n", m, e, n, c);
  bignum_from_int(&M, m);
  bignum_from_int(&E, e);
  bignum_from_int(&N, n);
  pow_mod_faster(&M, &E, &N, &C);
  c_result = bignum_to_int(&C);
  bignum_to_string(&C, buf, sizeof(buf));
  printf("  %d ^ %d mod %d = %d \n", m, e, n, c_result);
  printf("  %d ^ %d mod %d = %s \n", m, e, n, buf);

  printf("\n");

  printf("  Decrypting message c = %d \n", c);
  printf("  %d ^ %d mod %d = %d ? \n", c, d, n, m);
  pow_mod_faster(&C, &D, &N, &M);
  m_result = bignum_to_int(&M);
  bignum_to_string(&M, buf, sizeof(buf));
  printf("  %d ^ %d mod %d = %s \n", c, d, n, buf);
  printf("  %d ^ %d mod %d = %d \n", c, d, n, m_result);

  printf("\n");
}


void test_rsa_3(void)
{
  char buf[8192];


  const int p = 2053;
  const int q = 8209;
  const int n = p * q;
//int t = (p - 1) * (q - 1);
  const int e = 17;
  const int d = 2753;
  const int m = 123;
  const int c = 14837949;
  int m_result, c_result;

  bignum_init(&M);
  bignum_init(&C);
  bignum_init(&D);
  bignum_init(&E);
  bignum_init(&N);

  bignum_from_int(&D, d);
  bignum_from_int(&C, c);
  bignum_from_int(&N, n);

  printf("\n");

  printf("  Encrypting message m = %d \n", m);
  printf("  %d ^ %d mod %d = %d ? \n", m, e, n, c);
  bignum_from_int(&M, m);
  bignum_from_int(&E, e);
  bignum_from_int(&N, n);
  pow_mod_faster(&M, &E, &N, &C);
  c_result = bignum_to_int(&C);
  bignum_to_string(&C, buf, sizeof(buf));
  printf("  %d ^ %d mod %d = %d \n", m, e, n, c_result);
  printf("  %d ^ %d mod %d = %s \n", m, e, n, buf);

  printf("\n");

  printf("  Decrypting message c = %d \n", c);
  printf("  %d ^ %d mod %d = %d ? \n", c, d, n, m);
  pow_mod_faster(&C, &D, &N, &M);
  m_result = bignum_to_int(&M);
  bignum_to_string(&M, buf, sizeof(buf));
  printf("  %d ^ %d mod %d = %s \n", c, d, n, buf);
  printf("  %d ^ %d mod %d = %d \n", c, d, n, m_result);

  printf("\n");
}




struct bn n; /* public  key */
struct bn d; /* private key */
struct bn e; /* public exponent */
struct bn m; /* clear text message */
struct bn c; /* cipher text */

static void test_rsa1024(void)
{
  char public[]  = "a15f36fc7f8d188057fc51751962a5977118fa2ad4ced249c039ce36c8d1bd275273f1edd821892fa75680b1ae38749fff9268bf06b3c2af02bbdb52a0d05c2ae2384aa1002391c4b16b87caea8296cfd43757bb51373412e8fe5df2e56370505b692cf8d966e3f16bc62629874a0464a9710e4a0718637a68442e0eb1648ec5";
  char private[] = "3f5cc8956a6bf773e598604faf71097e265d5d55560c038c0bdb66ba222e20ac80f69fc6f93769cb795440e2037b8d67898d6e6d9b6f180169fc6348d5761ac9e81f6b8879529bc07c28dc92609eb8a4d15ac4ba3168a331403c689b1e82f62518c38601d58fd628fcb7009f139fb98e61ef7a23bee4e3d50af709638c24133d";
  char buf[8192];


  //int len_pub = strlen(public);
  //int len_prv = strlen(private);

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

//printf("  Copied %d bytes into m\n", i);

  printf("  Encrypting number x = %d \n", x);
  pow_mod_faster(&m, &e, &n, &c);
  printf("  Done...\n\n");

  bignum_to_string(&c, buf, sizeof(buf));
  printf("  Decrypting cipher text '");
  int i = 0;
  while (buf[i] != 0)
  {
    printf("%c", buf[i]);
    i += 1;
  }
  printf("'\n");

  /* Clear m */
  bignum_init(&m); 

  pow_mod_faster(&c, &d, &n, &m);
  printf("  Done...\n\n");


  bignum_to_string(&m, buf, sizeof(buf));
  printf("m = %s \n", buf);
}



static void test_rsa2048(void)
{
/*  
  char public[] = "f4f8fac0c1822f90c1ff35b817efa46256b70d77e12982653a375986e4512643de269599b2d10b660287bea5a73e768ae488a0d7d38abefecca5f65968be6acaa24453db4614bf7a185bbfd5730b5770944949288677701028ad644c234fff852b0c453651947be3a35a34a07d2736f83c9f126f50d77020cfc37f917995da89a9f561340661fcaf1a3324ac03adf960e242e648dfb9b7ca8bc7cdd18c75a00c202123a9032990859deee8de17457d5f71eb435b18276f82f7d65d6af966b9f33f93fd0714b8b311904daba68866b592762a47c6b7f6dc909a3123149b01b1c721fffa907b877784621ac8ec0aa3fe4f185636890a0fd327d8fde0a389adb4b1";
  char private[] = "40286523ce8a5602c78c1b79976b3fd63177c7a339e9312969d1cd34b2df3df2506032960a6b0d5d2e14772dd35b5c988bb9ecc619b520c882b884886e1250cdb929c3fc8da22973c4a562dc7840e429abec75a8936efc7e7ee8ca77d657c148133a27764e6f60f30179428735bfeb79a006d941261f0652d19715f5f7adf389cf36e879c2990e1da0ee67f218abbd5f42c82bbb696869dbc5a504465702c1c5d8b637930cebc80021ec25e048f59ee80aab5cb515a60d10ef01329b4cd543ed195b7e4af0d8f75e826b878f76392ce9afe4f935957536451f3dc4637235d831a669d986672ffd4c636d8d1cefedd72a3fdd20b084063e12a980a9068ff67b71";
  struct bn n;
  struct bn d;
  struct bn e;
  struct bn m;
  struct bn c;

  char plain[] = "hello"; // "hello friends"

  char hexplain[2*(sizeof plain / sizeof plain[0]) + 1];
  hexlify(plain, (sizeof plain / sizeof plain[0]) - 1, hexplain);
  printf(" hexlify(%s) = %s\n", plain, hexplain);
  
  bignum_init(&n);
  bignum_init(&d);
  bignum_init(&e);
  bignum_init(&m);
  bignum_init(&c);
  
  bignum_from_int(&e, 65537);
  bignum_from_string(&d, private, 256);
  
  bignum_from_string(&n, public,  256);
  
  bignum_from_string(&m, hexplain, (sizeof hexplain / sizeof hexplain[0]) -1);
  
  printf("  Encrypting number m = %s \n", hexplain);
  pow_mod_faster(&m, &e, &n, &c);
  printf("  Done...\n\n");

  char buf[8192];
  bignum_to_string(&c, buf, sizeof(buf));
  printf("Encrypted: %s\n", buf);
  printf("Done.\n");
  
*/
}

int main()
{
  setvbuf (stdout, NULL, _IONBF, BUFSIZ);
  printf("\n");
  printf("Testing RSA encryption implemented with bignum. \n");



  test_rsa_1();
  test_rsa_2();
  test_rsa_3();
  //test_rsa1024();

  printf("\n");
  printf("\n");



  return 0;
}



