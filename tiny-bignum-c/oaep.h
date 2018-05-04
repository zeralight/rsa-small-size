#ifndef _OAEP_H
#define _OAEP_H

#include <stdint.h>

typedef enum _lbl_t {
  LABEL_CLIENT = 0,
  LABEL_SERVER
} lbl_t;

/*
oaep_encode: pad a message M to the appropriate length for a given key
Arguments:
       M: the message to be encoded; must be exactly mLen bytes long
       k: the length in octets of the RSA modulus n; must be >= 74 (592 bits)
   label: one of two possible labels "CLNT" or "SRVR" (as above in lbl_t)
      EM: preallocated storage for the encoded message; must be at least k bytes long
Returns 0 on success.
Returns on error:
      -1: message too long (for the given key length)
      -2: unable to allocate memory
      -3: unable to obtain random bytes
*/
uint8_t oaep_encode(uint8_t *M, uint32_t mLen, uint32_t k, lbl_t label, uint8_t *EM);

#endif /* _OAEP_H */
