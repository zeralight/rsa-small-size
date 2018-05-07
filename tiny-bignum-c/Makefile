CC     := gcc
MACROS := 
CFLAGS := -I. -g -std=c99 -Wundef -Wall -Wextra -O3 $(MACROS)

pkcs_rsa_oaep_encrypt:
	$(CC) $(CFLAGS) bn.c rsa.c sha1.c oaep.c pkcs_rsa_oaep_encrypt.c -o ./build/pkcs_rsa_oaep_encrypt
rsa:
	$(CC) $(CFLAGS) -DRSA_MAIN bn.c ./rsa.c         -o ./build/test_rsa
sha1:
	$(CC) $(CFLAGS) -DSHA1_MAIN sha1.c -o ./build/sha1
oaep:
	$(CC) $(CFLAGS) -DTEST2  sha1.c oaep.c bn.c -o ./build/oaep
load_cmp: 
	$(CC) $(CFLAGS) -DBIGNUM_MAIN bn.c ./tests/load_cmp.c    -o ./build/test_load_cmp
factorial:
	$(CC) $(CFLAGS) bn.c ./tests/factorial.c   -o ./build/test_factorial



test:
	@echo
	@echo ================================================================================
	@./build/test_golden
	@echo ================================================================================
	@./build/test_hand_picked
	@echo ================================================================================
	@./build/test_load_cmp
	@echo ================================================================================
	@python ./scripts/fact100.py
	@./build/test_factorial
	@echo ================================================================================
	@python ./scripts/test_old_errors.py
	@echo ================================================================================
	@#./build/test_rsa
	@#echo ================================================================================
	@python ./scripts/test_rand.py 1000
	@echo ================================================================================
	@echo

clean:
	@rm -f ./build/*


