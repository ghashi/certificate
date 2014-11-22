#ifndef __NTRU_H_
#define __NTRU_H_

#include "libntru/src/ntru.h"

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define NTRU_INT_POLY_SIZE	(2 + 2 * NTRU_MAX_N)
#define NTRU_TERN_POLY_SIZE	(3 * 2 + 2 * (NTRU_MAX_ONES + NTRU_MAX_ONES))
#define NTRU_PROD_POLY_SIZE	(2 + 3 * NTRU_TERN_POLY_SIZE)
#define NTRU_PRIV_POLY_SIZE	MAX(NTRU_PROD_POLY_SIZE, NTRU_TERN_POLY_SIZE)
#define NTRU_ENC_PRIV_KEY_SIZE	(3 + NTRU_PRIV_POLY_SIZE)
#define NTRU_ENC_PUB_KEY_SIZE	(2 + NTRU_INT_POLY_SIZE)

#define NTRU_SKEY_SIZE		(NTRU_ENC_PRIV_KEY_SIZE)
#define NTRU_PKEY_SIZE		(NTRU_ENC_PUB_KEY_SIZE)

void ntru_keygen(unsigned char skey[NTRU_SKEY_SIZE], unsigned char pkey[NTRU_PKEY_SIZE]);
void ntru_encryption(const unsigned char pkey[NTRU_PKEY_SIZE], const char *plaintext, unsigned char *ciphertext);
void ntru_decryption(const unsigned char skey[NTRU_SKEY_SIZE], const unsigned char *ciphertext, char *plaintext);

#endif // __NTRU_H_
