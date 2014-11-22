#include "ecdsa.h"

void ecdsa_keygen(unsigned char skey[ECDSA_SKEY_SIZE], unsigned char pkey[ECDSA_PKEY_SIZE]) {
	uECC_make_key(pkey, skey);
}

void ecdsa_sign(const unsigned char skey[ECDSA_SKEY_SIZE], const unsigned char digest[ECDSA_DIGEST_SIZE], unsigned char signature[ECDSA_SIGNATURE_SIZE]) {
	uECC_sign(skey, digest, signature);
}

unsigned char ecdsa_verify(const unsigned char pkey[ECDSA_PKEY_SIZE], const unsigned char digest[ECDSA_DIGEST_SIZE], unsigned char signature[ECDSA_SIGNATURE_SIZE]) {
	return uECC_verify(pkey, digest, signature);
}

#ifdef ECDSA_SELFTEST

#include <stdio.h>
#include "util.h"

int main() {
	unsigned char skey[ECDSA_SKEY_SIZE], pkey[ECDSA_PKEY_SIZE], digest[ECDSA_DIGEST_SIZE], signature[ECDSA_SIGNATURE_SIZE];
	printf("ECDSA key generation... ");
	ecdsa_keygen(skey, pkey);
	printf("done!\n");
	Display("ECDSA skey:", skey, ECDSA_SKEY_SIZE);
	Display("ECDSA pkey:", pkey, ECDSA_PKEY_SIZE);
	printf("---------------\n");
	Display("digest:", digest, ECDSA_DIGEST_SIZE);
	printf("ECDSA signature... ");
	ecdsa_sign(skey, digest, signature);
	printf("done!\n");
	Display("signature:", signature, ECDSA_SIGNATURE_SIZE);
	printf("ECDSA verification... \n");
	if(ecdsa_verify(pkey, digest, signature))
		printf("ECDSA - OK\n");
	else
		printf("ECDSA - FAIL\n");
	return 0;
}

#endif // ECDSA_SELFTEST
