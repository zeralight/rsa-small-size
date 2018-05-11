CC     := gcc
MACROS := 
CFLAGS := -I. -I./src -std=c99 -g -Wundef -Wall -Wextra -O3 $(MACROS)

pkcs_oaep:
	$(CC) $(CFLAGS) src/util.c src/bn.c src/rsa.c src/sha1.c src/pkcs_oaep.c -o ./build/pkcs_oaep
rsa:
	$(CC) $(CFLAGS) -DIMPLEMENT_ALL -DRSA_MAIN src/util.c src/bn.c src/rsa.c         -o ./build/test_rsa
sha1:
	$(CC) $(CFLAGS) -DIMPLEMENT_ALL -DSHA1_MAIN src/util.c src/sha1.c -o ./build/sha1
load_cmp: 
	$(CC) $(CFLAGS) -DIMPLEMENT_ALL -DBIGNUM_MAIN src/util.c src/bn.c ./tests/load_cmp.c    -o ./build/test_load_cmp
factorial:
	$(CC) $(CFLAGS) -DIMPLEMENT_ALL -DFACTORIAL_MAIN src/util.c src/bn.c ./tests/factorial.c   -o ./build/test_factorial
golden:
	$(CC) $(CFLAGS) -DIMPLEMENT_ALL src/util.c src/bn.c ./tests/golden.c   -o ./build/golden

clean:
	@rm -f ./build/*


