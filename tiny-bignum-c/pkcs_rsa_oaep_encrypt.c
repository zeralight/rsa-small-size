#include <stdio.h>
#include <stdlib.h>

#include "rsa.h"
#include "oaep.h"

unsigned char* pkcs_rsa_oaep_encrypt(const unsigned char* from,
                                    uint32_t len,
                                    const unsigned char* n,
                                    uint32_t nlen,
                                    uint32_t e)
{
    unsigned char* padded = pkcs_oaep_mgf1_encode(from, len, RSA_KEYSIZE);
    printf("padding done\n"); fflush(stdout);
    unsigned char* hexlified = malloc(2*RSA_KEYSIZE);
    for (uint32_t i = 0; i < RSA_KEYSIZE; ++i)
    {
        uint8_t a = padded[i] >> 4;
        uint8_t b = padded[i] % 16;
        a += (a < 9 ? '0' : 'a');
        b += (b < 9 ? '0' : 'a');    
        hexlified[2*i] = a;
        hexlified[2*i+1] = b;
    }
    printf("hexlifying done\n"); fflush(stdout);
    unsigned char* encrypted = rsa_encrypt(hexlified, 2*RSA_KEYSIZE, n, nlen, e);
    printf("encryption done\n");
    free(padded);
    free(hexlified);

    return encrypted;
}

int main()
{
    unsigned char n[] = "f4f8fac0c1822f90c1ff35b817efa46256b70d77e12982653a375986e4512643de269599b2d10b660287bea5a73e768ae488a0d7d38abefecca5f65968be6acaa24453db4614bf7a185bbfd5730b5770944949288677701028ad644c234fff852b0c453651947be3a35a34a07d2736f83c9f126f50d77020cfc37f917995da89a9f561340661fcaf1a3324ac03adf960e242e648dfb9b7ca8bc7cdd18c75a00c202123a9032990859deee8de17457d5f71eb435b18276f82f7d65d6af966b9f33f93fd0714b8b311904daba68866b592762a47c6b7f6dc909a3123149b01b1c721fffa907b877784621ac8ec0aa3fe4f185636890a0fd327d8fde0a389adb4b1";
    //unsigned char d[] = "40286523ce8a5602c78c1b79976b3fd63177c7a339e9312969d1cd34b2df3df2506032960a6b0d5d2e14772dd35b5c988bb9ecc619b520c882b884886e1250cdb929c3fc8da22973c4a562dc7840e429abec75a8936efc7e7ee8ca77d657c148133a27764e6f60f30179428735bfeb79a006d941261f0652d19715f5f7adf389cf36e879c2990e1da0ee67f218abbd5f42c82bbb696869dbc5a504465702c1c5d8b637930cebc80021ec25e048f59ee80aab5cb515a60d10ef01329b4cd543ed195b7e4af0d8f75e826b878f76392ce9afe4f935957536451f3dc4637235d831a669d986672ffd4c636d8d1cefedd72a3fdd20b084063e12a980a9068ff67b71";
    uint32_t e = 65537;

    unsigned char input[] = "I wonder if it will work";
    
    unsigned char* output = pkcs_rsa_oaep_encrypt(input, sizeof input - 1, n, sizeof n - 1, e);   

    printf("final output:\n");
    for (uint32_t i = 0; i < RSA_KEYSIZE; ++i)
        printf("%02x", output[i]);

    free(output);

}