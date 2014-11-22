#include "ntru.h"

#include <stdio.h>
#include <string.h>
#include "libntru/src/ntru.h"
#include "libntru/src/err.h"

#ifdef NTRU_SELFTEST

#include <stdlib.h>
#include <time.h>

#define NTRU_TEST_N	100

#endif

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define NTRU_INT_POLY_SIZE	(2 + 2 * NTRU_MAX_N)
#define NTRU_TERN_POLY_SIZE	(3 * 2 + 2 * (NTRU_MAX_ONES + NTRU_MAX_ONES))
#define NTRU_PROD_POLY_SIZE	(2 + 3 * NTRU_TERN_POLY_SIZE)
#define NTRU_PRIV_POLY_SIZE	MAX(NTRU_PROD_POLY_SIZE, NTRU_TERN_POLY_SIZE)
#define NTRU_ENC_PRIV_KEY_SIZE	(3 + NTRU_PRIV_POLY_SIZE)
#define NTRU_ENC_PUB_KEY_SIZE	(2 + NTRU_INT_POLY_SIZE)

#define NTRU_SKEY_SIZE		(NTRU_ENC_PRIV_KEY_SIZE)
#define NTRU_PKEY_SIZE		(NTRU_ENC_PUB_KEY_SIZE)

#define	NTRU_BUFFER_SIZE	1000

void serialize_ntru_skey(NtruEncPrivKey *skey, unsigned char buffer[NTRU_SKEY_SIZE]);
void deserialize_ntru_skey(NtruEncPrivKey *skey, unsigned char buffer[NTRU_SKEY_SIZE]);
void serialize_ntru_pkey(NtruEncPubKey *pkey, unsigned char buffer[NTRU_PKEY_SIZE]);
void deserialize_ntru_pkey(NtruEncPubKey *pkey, unsigned char buffer[NTRU_PKEY_SIZE]);

NtruEncParams params = EES613EP1;
NtruRandContext rand_ctx;
NtruRandGen rng = NTRU_RNG_DEFAULT;

void ntru_keygen(unsigned char *skey, unsigned char *pkey) {
	NtruEncKeyPair kp;
	ntru_rand_init(&rand_ctx, &rng);
	while(ntru_gen_key_pair(&params, &kp, &rand_ctx) != NTRU_SUCCESS);
	ntru_rand_release(&rand_ctx);
	//memcpy(skey, &kp.priv, NTRU_SKEY_SIZE);
	//memcpy(pkey, &kp.pub, NTRU_PKEY_SIZE);
	serialize_ntru_skey(&kp.priv, skey);
	serialize_ntru_pkey(&kp.pub, pkey);
}

void ntru_encryption(const unsigned char pkey[], const char *plaintext, unsigned char *ciphertext) {
	NtruEncPubKey ntru_pkey;
	//memcpy(&ntru_pkey, pkey, sizeof(NtruEncPubKey));
	deserialize_ntru_pkey(&ntru_pkey, pkey);
	ntru_rand_init(&rand_ctx, &rng);
	while(ntru_encrypt(plaintext, strlen(plaintext) + 1, &ntru_pkey, &params, &rand_ctx, ciphertext) != NTRU_SUCCESS);
	ntru_rand_release(&rand_ctx);
}

void ntru_decryption(const unsigned char skey[], const unsigned char *ciphertext, char *plaintext) {
	unsigned short plaintext_len = NTRU_BUFFER_SIZE;
	NtruEncKeyPair kp;
	//memcpy(&kp.priv, skey, sizeof(NtruEncPrivKey));
	deserialize_ntru_skey(&kp.priv, skey);
	ntru_decrypt(ciphertext, &kp, &params, plaintext, &plaintext_len);
	plaintext[plaintext_len] = '\0';
}

void serialize_short(short n, unsigned char buffer[2]) {
	memcpy(buffer, &n, sizeof(short));
}

short deserialize_short(unsigned char buffer[2]) {
	return ((short)(buffer[1] << 8) | buffer[0]);
}

#ifdef NTRU_SELFTEST

unsigned char test_short_serialization() {
	short i, n;
	unsigned char test = 1, buffer[2];
	for(i = 0; i < NTRU_TEST_N; i++) {
		n = rand();
		serialize_short(n, buffer);
		if(deserialize_short(buffer) != n) {
			printf("Serialization short - Fail\n");
			test = 0;
			break;
		}
	}
	return test;
}

#endif // NTRU_SELFTEST

void serialize_ntru_int_poly(NtruIntPoly *ntru_int_poly, unsigned char buffer[NTRU_INT_POLY_SIZE]) {
	unsigned int i, index = 0;
	serialize_short(ntru_int_poly->N, buffer);
	index += sizeof(short);
	for(i = 0; i < NTRU_MAX_N; i++) {
		serialize_short(ntru_int_poly->coeffs[i], buffer + index);
		index += sizeof(short);
	}
}

void deserialize_ntru_int_poly(NtruIntPoly *ntru_int_poly, unsigned char buffer[NTRU_INT_POLY_SIZE]) {
	unsigned int i, index = 0;
	ntru_int_poly->N = deserialize_short(buffer);
	index += sizeof(short);
	for(i = 0; i < NTRU_MAX_N; i++) {
		ntru_int_poly->coeffs[i] = deserialize_short(buffer + index);
		index += sizeof(short);
	}
}

#ifdef NTRU_SELFTEST

void rand_ntru_int_poly(NtruIntPoly *ntru_int_poly) {
	ntru_int_poly->N = rand();
	unsigned int i;
	for(i = 0; i < NTRU_MAX_N; i++)
		ntru_int_poly->coeffs[i] = rand();
}

unsigned char test_ntru_int_poly_serialization() {
	short i;
	unsigned char test = 1, buffer[NTRU_INT_POLY_SIZE];
	NtruIntPoly ntru_int_poly, ntru_int_poly_test;
	for(i = 0; i < NTRU_TEST_N; i++) {
		rand_ntru_int_poly(&ntru_int_poly);
		serialize_ntru_int_poly(&ntru_int_poly, buffer);
		deserialize_ntru_int_poly(&ntru_int_poly_test, buffer);
		if(memcmp(&ntru_int_poly, &ntru_int_poly_test, NTRU_INT_POLY_SIZE) != 0) {
			printf("Serialization NtruIntPoly - Fail\n");
			test = 0;
			break;
		}
	}
	return test;
}

#endif // NTRU_SELFTEST

void serialize_ntru_tern_poly(NtruTernPoly *ntru_tern_poly, unsigned char buffer[NTRU_TERN_POLY_SIZE]) {
	unsigned int i, index = 0;
	serialize_short(ntru_tern_poly->N, buffer);
	index += sizeof(short);
	serialize_short(ntru_tern_poly->num_ones, buffer + index);
	index += sizeof(short);
	serialize_short(ntru_tern_poly->num_neg_ones, buffer + index);
	index += sizeof(short);
	for(i = 0; i < NTRU_MAX_ONES; i++) {
		serialize_short(ntru_tern_poly->ones[i], buffer + index);
		index += sizeof(short);
	}
	for(i = 0; i < NTRU_MAX_ONES; i++) {
		serialize_short(ntru_tern_poly->neg_ones[i], buffer + index);
		index += sizeof(short);
	}
}

void deserialize_ntru_tern_poly(NtruTernPoly *ntru_tern_poly, unsigned char buffer[NTRU_TERN_POLY_SIZE]) {
	unsigned int i, index = 0;
	ntru_tern_poly->N = deserialize_short(buffer);
	index += sizeof(short);
	ntru_tern_poly->num_ones = deserialize_short(buffer + index);
	index += sizeof(short);
	ntru_tern_poly->num_neg_ones = deserialize_short(buffer + index);
	index += sizeof(short);
	for(i = 0; i < NTRU_MAX_ONES; i++) {
		ntru_tern_poly->ones[i] = deserialize_short(buffer + index);
		index += sizeof(short);
	}
	for(i = 0; i < NTRU_MAX_ONES; i++) {
		ntru_tern_poly->neg_ones[i] = deserialize_short(buffer + index);
		index += sizeof(short);
	}
}

#ifdef NTRU_SELFTEST

void rand_ntru_tern_poly(NtruTernPoly *ntru_tern_poly) {
	ntru_tern_poly->N = rand();
	ntru_tern_poly->num_ones = rand();
	ntru_tern_poly->num_neg_ones = rand();
	unsigned int i;
	for(i = 0; i < NTRU_MAX_N; i++) {
		ntru_tern_poly->ones[i] = rand();
		ntru_tern_poly->neg_ones[i] = rand();
	}
}

unsigned char test_ntru_tern_poly_serialization() {
	short i;
	unsigned char test = 1, buffer[NTRU_INT_POLY_SIZE];
	NtruTernPoly ntru_tern_poly, ntru_tern_poly_test;
	for(i = 0; i < NTRU_TEST_N; i++) {
		rand_ntru_tern_poly(&ntru_tern_poly);
		serialize_ntru_tern_poly(&ntru_tern_poly, buffer);
		deserialize_ntru_tern_poly(&ntru_tern_poly_test, buffer);
		if(memcmp(&ntru_tern_poly, &ntru_tern_poly_test, NTRU_TERN_POLY_SIZE) != 0) {
			printf("Serialization NtruTernPoly - Fail\n");
			test = 0;
			break;
		}
	}
	return test;
}

#endif // NTRU_SELFTEST

void serialize_ntru_prod_poly(NtruProdPoly *ntru_prod_poly, unsigned char buffer[NTRU_PROD_POLY_SIZE]) {
	unsigned int index = 0;
	serialize_short(ntru_prod_poly->N, buffer);
	index += sizeof(short);
	serialize_ntru_tern_poly(&ntru_prod_poly->f1, buffer + index);
	index += sizeof(NtruTernPoly);
	serialize_ntru_tern_poly(&ntru_prod_poly->f2, buffer + index);
	index += sizeof(NtruTernPoly);
	serialize_ntru_tern_poly(&ntru_prod_poly->f3, buffer + index);
	index += sizeof(NtruTernPoly);
}

void deserialize_ntru_prod_poly(NtruProdPoly *ntru_prod_poly, unsigned char buffer[NTRU_PROD_POLY_SIZE]) {
	unsigned int index = 0;
	ntru_prod_poly->N = deserialize_short(buffer);
	index += sizeof(short);
	deserialize_ntru_tern_poly(&ntru_prod_poly->f1, buffer + index);
	index += sizeof(NtruTernPoly);
	deserialize_ntru_tern_poly(&ntru_prod_poly->f2, buffer + index);
	index += sizeof(NtruTernPoly);
	deserialize_ntru_tern_poly(&ntru_prod_poly->f3, buffer + index);
	index += sizeof(NtruTernPoly);
}

#ifdef NTRU_SELFTEST

void rand_ntru_prod_poly(NtruProdPoly *ntru_prod_poly) {
	ntru_prod_poly->N = rand();
	rand_ntru_tern_poly(&ntru_prod_poly->f1);
	rand_ntru_tern_poly(&ntru_prod_poly->f2);
	rand_ntru_tern_poly(&ntru_prod_poly->f3);
}

unsigned char test_ntru_prod_poly_serialization() {
	short i;
	unsigned char test = 1, buffer[NTRU_PROD_POLY_SIZE];
	NtruProdPoly ntru_prod_poly, ntru_prod_poly_test;
	for(i = 0; i < NTRU_TEST_N; i++) {
		rand_ntru_prod_poly(&ntru_prod_poly);
		serialize_ntru_prod_poly(&ntru_prod_poly, buffer);
		deserialize_ntru_prod_poly(&ntru_prod_poly_test, buffer);
		if(memcmp(&ntru_prod_poly, &ntru_prod_poly_test, NTRU_PROD_POLY_SIZE) != 0) {
			printf("Serialization NtruProdPoly - Fail\n");
			test = 0;
			break;
		}
	}
	return test;
}

#endif // NTRU_SELFTEST

void serialize_ntru_priv_poly(NtruPrivPoly *ntru_priv_poly, unsigned char buffer[NTRU_PRIV_POLY_SIZE]) {
	//printf("SIZE NTRU_PRIV_POLY_SIZE: %d\n", NTRU_PRIV_POLY_SIZE);
	//printf("sizeof(NtruPrivPoly): %d\n", sizeof(NtruPrivPoly));
	//Display(">>>>>>>>> NtruPrivPoly", buffer, sizeof(NtruPrivPoly));
	serialize_ntru_prod_poly(&ntru_priv_poly->prod, buffer);
	//Display(">>>>>>>>> NtruPrivPoly", buffer, NTRU_PRIV_POLY_SIZE);
}

void deserialize_ntru_priv_poly(NtruPrivPoly *ntru_priv_poly, unsigned char buffer[NTRU_PRIV_POLY_SIZE]) {
	deserialize_ntru_prod_poly(&ntru_priv_poly->prod, buffer);
}

#ifdef NTRU_SELFTEST

void rand_ntru_priv_poly(NtruPrivPoly *ntru_priv_poly) {
	rand_ntru_prod_poly(&ntru_priv_poly->prod);
}

unsigned char test_ntru_priv_poly_serialization() {
	short i;
	unsigned char test = 1, buffer[NTRU_PRIV_POLY_SIZE];
	NtruPrivPoly ntru_priv_poly, ntru_priv_poly_test;
	for(i = 0; i < NTRU_TEST_N; i++) {
		rand_ntru_priv_poly(&ntru_priv_poly);
		serialize_ntru_priv_poly(&ntru_priv_poly, buffer);
		deserialize_ntru_priv_poly(&ntru_priv_poly_test, buffer);
		if(memcmp(&ntru_priv_poly, &ntru_priv_poly_test, NTRU_PRIV_POLY_SIZE) != 0) {
			printf("Serialization NtruPrivPoly - Fail\n");
			test = 0;
			break;
		}
	}
	return test;
}

#endif // NTRU_SELFTEST

void serialize_ntru_enc_priv_key(NtruEncPrivKey *ntru_enc_priv_key, unsigned char buffer[NTRU_ENC_PRIV_KEY_SIZE]) {
	unsigned int index = 0;
	memset(buffer, 0, NTRU_ENC_PRIV_KEY_SIZE);
	serialize_short(ntru_enc_priv_key->q, buffer);
	index += sizeof(short);
	buffer[index++] = ntru_enc_priv_key->prod_flag;
	serialize_ntru_priv_poly(&ntru_enc_priv_key->t, buffer + index);
	index += sizeof(NtruPrivPoly);
	//printf(">>>>>>>>>>>> %d\n", buffer[3]);
	//printf("::::::::::%d %d\n", ntru_enc_priv_key->q, ntru_enc_priv_key->prod_flag);
	//Display("::::::::::::NtruEncPrivKey", buffer, 3);
}

void deserialize_ntru_enc_priv_key(NtruEncPrivKey *ntru_enc_priv_key, unsigned char buffer[NTRU_ENC_PRIV_KEY_SIZE]) {
	unsigned int index = 0;
	memset(ntru_enc_priv_key, 0, sizeof(ntru_enc_priv_key));
	ntru_enc_priv_key->q = deserialize_short(buffer);
	index += sizeof(short);
	ntru_enc_priv_key->prod_flag = buffer[index++];
	deserialize_ntru_priv_poly(&ntru_enc_priv_key->t, buffer + index);
	index += sizeof(NtruPrivPoly);
	//printf(">>>>>>>>>>>> %d\n", buffer[3]);
	//printf(">>>>>>>>>>>> %d\n", ntru_enc_priv_key->t);
	//printf("::::::::::%d %d\n", ntru_enc_priv_key->q, ntru_enc_priv_key->prod_flag);
}

#ifdef NTRU_SELFTEST

void rand_ntru_enc_priv_key(NtruEncPrivKey *ntru_enc_priv_key) {
	ntru_enc_priv_key->q = rand();
	ntru_enc_priv_key->prod_flag = rand();
	rand_ntru_priv_poly(&ntru_enc_priv_key->t);
}

unsigned char test_ntru_enc_priv_key_serialization() {
	short i;
	unsigned char test = 1, buffer[NTRU_ENC_PRIV_KEY_SIZE];
	NtruEncPrivKey ntru_enc_priv_key, ntru_enc_priv_key_test;
	for(i = 0; i < NTRU_TEST_N; i++) {
		rand_ntru_enc_priv_key(&ntru_enc_priv_key);
		serialize_ntru_enc_priv_key(&ntru_enc_priv_key, buffer);
		deserialize_ntru_enc_priv_key(&ntru_enc_priv_key_test, buffer);
		//Display(":::::::::::::: ntru_enc_priv_key", &ntru_enc_priv_key, NTRU_ENC_PRIV_KEY_SIZE);
		//Display(":::::::::::::: ntru_enc_priv_key_test", &ntru_enc_priv_key_test, NTRU_ENC_PRIV_KEY_SIZE);
		//printf(">>>>>>> %d", memcmp(&ntru_enc_priv_key, &ntru_enc_priv_key_test, NTRU_ENC_PRIV_KEY_SIZE));
		if(memcmp(&ntru_enc_priv_key, &ntru_enc_priv_key_test, NTRU_ENC_PRIV_KEY_SIZE) != 0) {
			printf("Serialization NtruEncPrivKey - Fail\n");
			test = 0;
			break;
		}
	}
	return test;
}

#endif // NTRU_SELFTEST

void serialize_ntru_enc_pub_key(NtruEncPubKey *ntru_enc_pub_key, unsigned char buffer[NTRU_ENC_PUB_KEY_SIZE]) {
	unsigned int index = 0;
	serialize_short(ntru_enc_pub_key->q, buffer);
	index += sizeof(short);
	serialize_ntru_int_poly(&ntru_enc_pub_key->h, buffer + index);
	index += sizeof(NtruIntPoly);
}

void deserialize_ntru_enc_pub_key(NtruEncPubKey *ntru_enc_pub_key, unsigned char buffer[NTRU_ENC_PUB_KEY_SIZE]) {
	unsigned int index = 0;
	ntru_enc_pub_key->q = deserialize_short(buffer);
	index += sizeof(short);
	deserialize_ntru_int_poly(&ntru_enc_pub_key->h, buffer + index);
	index += sizeof(NtruIntPoly);
}

#ifdef NTRU_SELFTEST

void rand_ntru_enc_pub_key(NtruEncPubKey *ntru_enc_pub_key) {
	ntru_enc_pub_key->q = rand();
	rand_ntru_int_poly(&ntru_enc_pub_key->h);
}

unsigned char test_ntru_enc_pub_key_serialization() {
	short i;
	unsigned char test = 1, buffer[NTRU_ENC_PUB_KEY_SIZE];
	NtruEncPubKey ntru_enc_pub_key, ntru_enc_pub_key_test;
	for(i = 0; i < NTRU_TEST_N; i++) {
		rand_ntru_enc_pub_key(&ntru_enc_pub_key);
		serialize_ntru_enc_pub_key(&ntru_enc_pub_key, buffer);
		deserialize_ntru_enc_pub_key(&ntru_enc_pub_key_test, buffer);
		if(memcmp(&ntru_enc_pub_key, &ntru_enc_pub_key_test, NTRU_ENC_PUB_KEY_SIZE) != 0) {
			printf("Serialization NtruEncPubKey - Fail\n");
			test = 0;
			break;
		}
	}
	return test;
}

#endif // NTRU_SELFTEST

void serialize_ntru_skey(NtruEncPrivKey *skey, unsigned char buffer[NTRU_SKEY_SIZE]) {
	serialize_ntru_enc_priv_key(skey, buffer);
}

void deserialize_ntru_skey(NtruEncPrivKey *skey, unsigned char buffer[NTRU_SKEY_SIZE]) {
	deserialize_ntru_enc_priv_key(skey, buffer);
}

#ifdef NTRU_SELFTEST

void rand_ntru_skey(NtruEncPrivKey *ntru_skey) {
	rand_ntru_enc_priv_key(ntru_skey);
}

unsigned char test_ntru_skey_serialization() {
	short i;
	unsigned char test = 1, buffer[NTRU_SKEY_SIZE];
	NtruEncPrivKey ntru_skey, ntru_skey_test;
	for(i = 0; i < NTRU_TEST_N; i++) {
		rand_ntru_skey(&ntru_skey);
		serialize_ntru_skey(&ntru_skey, buffer);
		deserialize_ntru_skey(&ntru_skey_test, buffer);
		if(memcmp(&ntru_skey, &ntru_skey_test, NTRU_SKEY_SIZE) != 0) {
			printf("Serialization NTRU skey - Fail\n");
			test = 0;
			break;
		}
	}
	return test;
}

#endif // NTRU_SELFTEST

void serialize_ntru_pkey(NtruEncPubKey *pkey, unsigned char buffer[NTRU_PKEY_SIZE]) {
	serialize_ntru_enc_pub_key(pkey, buffer);
}

void deserialize_ntru_pkey(NtruEncPubKey *pkey, unsigned char buffer[NTRU_PKEY_SIZE]) {
	deserialize_ntru_enc_pub_key(pkey, buffer);
}

#ifdef	NTRU_SELFTEST

void rand_ntru_pkey(NtruEncPubKey *ntru_pkey) {
	rand_ntru_enc_pub_key(ntru_pkey);
}

unsigned char test_ntru_pkey_serialization() {
	short i;
	unsigned char test = 1, buffer[NTRU_SKEY_SIZE];
	NtruEncPubKey ntru_pkey, ntru_pkey_test;
	for(i = 0; i < NTRU_TEST_N; i++) {
		rand_ntru_pkey(&ntru_pkey);
		serialize_ntru_pkey(&ntru_pkey, buffer);
		deserialize_ntru_pkey(&ntru_pkey_test, buffer);
		if(memcmp(&ntru_pkey, &ntru_pkey_test, NTRU_PKEY_SIZE) != 0) {
			printf("Serialization NTRU pkey - Fail\n");
			test = 0;
			break;
		}
	}
	return test;
}

#endif // NTRU_SELFTEST

#ifdef NTRU_SELFTEST

#include "util.h" 

int main() {
	srand(time(NULL));
	printf("Testing serialization...\n");
	if(test_short_serialization())
		printf("Serialization short - Ok\n");
	if(test_ntru_int_poly_serialization())
		printf("Serialization NtruIntPoly - Ok\n");
	if(test_ntru_tern_poly_serialization())
		printf("Serialization NtruTernPoly - Ok\n");
	if(test_ntru_prod_poly_serialization())
		printf("Serialization NtruProdPoly - Ok\n");
	if(test_ntru_priv_poly_serialization())
		printf("Serialization NtruPrivPoly - Ok\n");
	if(test_ntru_enc_priv_key_serialization())
		printf("Serialization NtruEncPrivKey - Ok\n");
	if(test_ntru_enc_pub_key_serialization())
		printf("Serialization NtruEncPubKey - Ok\n");
	if(test_ntru_skey_serialization())
		printf("Serialization NTRU SKEY - Ok\n");
	if(test_ntru_pkey_serialization())
		printf("Serialization NTRU PKEY - Ok\n");
	printf("=================================\n");
	unsigned char skey[NTRU_SKEY_SIZE], pkey[NTRU_PKEY_SIZE];
	printf("SKEY SIZE: %d\n", NTRU_SKEY_SIZE);
	printf("PKEY SIZE: %d\n", NTRU_PKEY_SIZE);
	//fprintf(stderr, "Generating Keypair...");
	printf("Generating Keypair...");
	ntru_keygen(skey, pkey);
	printf(" done!\n");
	Display("skey:", skey, NTRU_SKEY_SIZE);
	Display("pkey:", pkey, NTRU_PKEY_SIZE);
	char plaintext[NTRU_BUFFER_SIZE], ciphertext[NTRU_BUFFER_SIZE];
	strcpy(plaintext, "test message 12345");
	printf("--------------\n");
	printf("max plaintext length: %d\n", ntru_max_msg_len(&params));
	printf("plaintext: %s\n", plaintext);
	unsigned short ciphertext_len = ntru_enc_len(&params);
	printf("ciphertext lenght (pre-computed): %d\n", ciphertext_len);
	printf("Encrypting plaintext... ");
	ntru_encryption(pkey, plaintext, ciphertext);
	printf(" done!\n");
	Display("ciphertext:", ciphertext, ciphertext_len);
	printf("Decrypting ciphertext... ");
	memset(plaintext, 1, NTRU_BUFFER_SIZE);
	ntru_decryption(skey, ciphertext, plaintext);
	printf(" done!\n");
	printf("plaintext: %s\n", plaintext);
	return 0;
}

#endif // NTRU_SELFTEST
