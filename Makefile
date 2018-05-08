CC     := gcc
MACROS := 
CFLAGS := -I. -g -std=c99 -Wundef -Wall -Wextra -O3 $(MACROS)

pkcs_oaep:
	$(CC) $(CFLAGS) src/util.c src/bn.c src/rsa.c src/sha1.c src/pkcs_oaep.c -o ./build/pkcs_oaep
rsa:
	$(CC) $(CFLAGS) -DRSA_MAIN src/util.c src/bn.c src/rsa.c         -o ./build/rsa
sha1:
	$(CC) $(CFLAGS) -DSHA1_MAIN src/util.c src/sha1.c -o ./build/sha1
load_cmp: 
	$(CC) $(CFLAGS) -DBIGNUM_MAIN util.c bn.c ./tests/load_cmp.c    -o ./build/test_load_cmp
factorial:
	$(CC) $(CFLAGS) bn.c ./tests/factorial.c   -o ./build/test_factorial

clean:
	@rm -f ./build/*


