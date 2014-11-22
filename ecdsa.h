#ifndef __ECDSA_H_
#define __ECDSA_H_

#include "uECC.h"

#define ECDSA_SKEY_SIZE		(uECC_BYTES)
#define ECDSA_PKEY_SIZE		(2 * uECC_BYTES)
#define ECDSA_SIGNATURE_SIZE 	(2 * uECC_BYTES)
#define ECDSA_DIGEST_SIZE 	(uECC_BYTES)

void ecdsa_keygen(unsigned char skey[ECDSA_SKEY_SIZE], unsigned char pkey[ECDSA_PKEY_SIZE]);
void ecdsa_sign(const unsigned char skey[ECDSA_SKEY_SIZE], const unsigned  char digest[ECDSA_DIGEST_SIZE], unsigned char signature[ECDSA_SIGNATURE_SIZE]);
unsigned char ecdsa_verify(const unsigned char pkey[ECDSA_PKEY_SIZE], const unsigned char digest[ECDSA_DIGEST_SIZE], unsigned char signature[ECDSA_SIGNATURE_SIZE]);

#endif // __ECDSA_H_
