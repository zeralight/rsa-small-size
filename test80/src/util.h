#ifndef __UTIL__
#define __UTIL__

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#ifdef __H8_2329F__
#define BIG_ENDIAN
#endif



#ifdef NDEBUG
	#define require(p, msg) ((void)0)
#else
	#ifdef __H8_2329F__
		extern void _CLOSEALL(void);
		#define require(p, msg) { if (!(p) ) { fprintf(stderr, "%s\n", msg); _CLOSEALL(); } }
	#else
		#define require(p, msg) assert (p && #msg)
	#endif
#endif


//#define HEAP_SIZE 0x51a0
#define HEAP_SIZE 0x5958 // 44*514 + 256

struct heap {
	char *buf, *brk;
	uint32_t size;
};
extern struct heap heap;

void *heap_get(uint32_t n);
void heap_free(uint32_t n);

void i2osp(void* dest, const void* src, uint32_t len);
void print_hex(const unsigned char* bytes, uint32_t len);
void unhexlify(const unsigned char* hex, uint32_t len, unsigned char* dest);


/*
int memcmp(const void *a, const void *b, uint32_t nb);
void memcpy(void *dest, const void *src, uint32_t nb);
void memset(void *src, int val, uint32_t nb);
*/
#endif