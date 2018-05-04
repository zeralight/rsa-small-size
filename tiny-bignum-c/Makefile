CC     := gcc
MACROS := 
CFLAGS := -std=c99 -I. -Wundef -Wall -Wextra -O3 $(MACROS)


all:
	$(CC) $(CFLAGS) bn.c ./tests/factorial.c   -o ./build/test_factorial
	$(CC) $(CFLAGS) *.c ./tests/rsa.c         -o ./build/test_rsa


