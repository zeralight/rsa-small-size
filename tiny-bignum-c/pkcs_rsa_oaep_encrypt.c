#include <stdio.h>
#include <stdlib.h>

#include "oaep.h"

#include "rsa.h"
#include "bn.h"

unsigned char* pkcs_rsa_oaep_encrypt(const unsigned char* from,
                                    uint32_t len,
                                    const unsigned char* n,
                                    uint32_t nlen,
                                    uint32_t e)
{
    unsigned char* padded = pkcs_oaep_mgf1_encode(from, len, RSA_KEYSIZE);
    printf("padded input: "); print_hex(padded, RSA_KEYSIZE);
    printf("padding done\n"); fflush(stdout);

    unsigned char* encrypted;
    if (nlen == 2*RSA_KEYSIZE) // hex input
    {
        unsigned char* unhexlified_n = malloc(RSA_KEYSIZE);
        for (uint32_t i = 0; i < RSA_KEYSIZE; ++i)
        {
            uint8_t a = n[2*i];
            uint8_t b = n[2*i+1];
            a -= (a < '9') ? '0' : 'a'-10;
            b -= (b < '9') ? '0' : 'a'-10;
            unhexlified_n[i] = (a << 4) + b;
        }
        printf("bytes n: "); print_hex(unhexlified_n, RSA_KEYSIZE);
        printf("unhexlifying done\n"); fflush(stdout);

        encrypted = rsa_encrypt(padded, len, unhexlified_n, RSA_KEYSIZE, e);
        free(unhexlified_n);
    }
    else // binary input
    {
        encrypted = rsa_encrypt(padded, len, n, RSA_KEYSIZE, e);
    }

    printf("encryption done\n");
    free(padded);
    // free(hexlified);

    return encrypted;
}

unsigned char* pkcs_rsa_oaep_decrypt(const unsigned char* from,
                                    uint32_t flen,
                                    const unsigned char* n,
                                    uint32_t nlen,
                                    const unsigned char* d,
                                    uint32_t dlen)
{
    printf("RSA decrypting...\n");
    unsigned char* decrypted = rsa_decrypt(from, flen, n, nlen, d, dlen);
    printf("\nRsa Decryption done.\n");
    printf("decrypted bytes: "); print_hex(decrypted, RSA_KEYSIZE);

    printf("Unpadding..\n");
    unsigned char* unpadded = pkcs_oaep_mgf1_decode(decrypted, RSA_KEYSIZE);
    printf("Unpadding done.\n");
    printf("Unpadded bytes: "); print_hex(unpadded, 10);

    free(decrypted);
    return unpadded;
}

int main()
{
    //unsigned char n[] = "\xf4\xf8\xfa\xc0\xc1\x82/\x90\xc1\xff5\xb8\x17\xef\xa4bV\xb7\rw\xe1)\x82e:7Y\x86\xe4Q&C\xde&\x95\x99\xb2\xd1\x0bf\x02\x87\xbe\xa5\xa7>v\x8a\xe4\x88\xa0\xd7\xd3\x8a\xbe\xfe\xcc\xa5\xf6Yh\xbej\xca\xa2DS\xdbF\x14\xbfz\x18[\xbf\xd5s\x0bWp\x94II(\x86wp\x10(\xaddL#O\xff\x85+\x0cE6Q\x94{\xe3\xa3Z4\xa0}'6\xf8<\x9f\x12oP\xd7p \xcf\xc3\x7f\x91y\x95\xda\x89\xa9\xf5a4\x06a\xfc\xaf\x1a3$\xac\x03\xad\xf9`\xe2B\xe6H\xdf\xb9\xb7\xca\x8b\xc7\xcd\xd1\x8cu\xa0\x0c !#\xa9\x03)\x90\x85\x9d\xee\xe8\xde\x17E}_q\xebC[\x18'o\x82\xf7\xd6]j\xf9f\xb9\xf3?\x93\xfd\x07\x14\xb8\xb3\x11\x90M\xab\xa6\x88f\xb5\x92v*G\xc6\xb7\xf6\xdc\x90\x9a1#\x14\x9b\x01\xb1\xc7!\xff\xfa\x90{\x87w\x84b\x1a\xc8\xec\n\xa3\xfeO\x18V6\x89\n\x0f\xd3'\xd8\xfd\xe0\xa3\x89\xad\xb4\xb1";
    //unsigned char d[] = "@(e#\xce\x8aV\x02\xc7\x8c\x1by\x97k?\xd61w\xc7\xa39\xe91)i\xd1\xcd4\xb2\xdf=\xf2P`2\x96\nk\r].\x14w-\xd3[\\\x98\x8b\xb9\xec\xc6\x19\xb5 \xc8\x82\xb8\x84\x88n\x12P\xcd\xb9)\xc3\xfc\x8d\xa2)s\xc4\xa5b\xdcx@\xe4)\xab\xecu\xa8\x93n\xfc~~\xe8\xcaw\xd6W\xc1H\x13:'vNo`\xf3\x01yB\x875\xbf\xeby\xa0\x06\xd9A&\x1f\x06R\xd1\x97\x15\xf5\xf7\xad\xf3\x89\xcf6\xe8y\xc2\x99\x0e\x1d\xa0\xeeg\xf2\x18\xab\xbd_B\xc8+\xbbihi\xdb\xc5\xa5\x04FW\x02\xc1\xc5\xd8\xb67\x93\x0c\xeb\xc8\x00!\xec%\xe0H\xf5\x9e\xe8\n\xab\\\xb5\x15\xa6\r\x10\xef\x012\x9bL\xd5C\xed\x19[~J\xf0\xd8\xf7^\x82k\x87\x8fv9,\xe9\xaf\xe4\xf95\x95u6E\x1f=\xc4cr5\xd81\xa6i\xd9\x86g/\xfdLcm\x8d\x1c\xef\xed\xd7*?\xdd \xb0\x84\x06>\x12\xa9\x80\xa9\x06\x8f\xf6{q";

    unsigned char n[] = "f4f8fac0c1822f90c1ff35b817efa46256b70d77e12982653a375986e4512643de269599b2d10b660287bea5a73e768ae488a0d7d38abefecca5f65968be6acaa24453db4614bf7a185bbfd5730b5770944949288677701028ad644c234fff852b0c453651947be3a35a34a07d2736f83c9f126f50d77020cfc37f917995da89a9f561340661fcaf1a3324ac03adf960e242e648dfb9b7ca8bc7cdd18c75a00c202123a9032990859deee8de17457d5f71eb435b18276f82f7d65d6af966b9f33f93fd0714b8b311904daba68866b592762a47c6b7f6dc909a3123149b01b1c721fffa907b877784621ac8ec0aa3fe4f185636890a0fd327d8fde0a389adb4b1";
    unsigned char d[] = "40286523ce8a5602c78c1b79976b3fd63177c7a339e9312969d1cd34b2df3df2506032960a6b0d5d2e14772dd35b5c988bb9ecc619b520c882b884886e1250cdb929c3fc8da22973c4a562dc7840e429abec75a8936efc7e7ee8ca77d657c148133a27764e6f60f30179428735bfeb79a006d941261f0652d19715f5f7adf389cf36e879c2990e1da0ee67f218abbd5f42c82bbb696869dbc5a504465702c1c5d8b637930cebc80021ec25e048f59ee80aab5cb515a60d10ef01329b4cd543ed195b7e4af0d8f75e826b878f76392ce9afe4f935957536451f3dc4637235d831a669d986672ffd4c636d8d1cefedd72a3fdd20b084063e12a980a9068ff67b71";
    uint32_t e = 0x10001;

    unsigned char input[] = "I wonder if it will work";
    
    unsigned char* output = pkcs_rsa_oaep_encrypt(input, sizeof input - 1, n, sizeof n - 1, e);

    printf("cipher:\n");
    for (uint32_t i = 0; i < RSA_KEYSIZE; ++i)
        printf("%02x", output[i]);
    printf("\n");

    unsigned char* plain = pkcs_rsa_oaep_decrypt(output, RSA_KEYSIZE, n, RSA_KEYSIZE, d, RSA_KEYSIZE);


    free(plain);
    free(output);

}