#include "certificate.h"

#include "util.h"
#include "sponge.h"
#include <stdio.h>
#include <string.h>

// csr info :: (id || cname || time || auth_key || token_key)
// 	return - size in bytes of the appended data
unsigned int csr_append_info(unsigned char buffer[], unsigned int id, const char *cname, const char time[TIME_BUFFER_SIZE], const unsigned char auth_key[SMQV_PKEY_SIZE], const unsigned char token_key[MSS_PKEY_SIZE]);
unsigned int csr_split_info(const unsigned char buffer[], unsigned int *id, char *cname, char time[TIME_BUFFER_SIZE], unsigned char auth_key[SMQV_PKEY_SIZE], unsigned char token_key[MSS_PKEY_SIZE], unsigned char csr_signature[MSS_SIGNATURE_SIZE]);

// cert info :: (id || cname || time || valid || auth_key || token_key)
// 	return - size in bytes of the appended data
unsigned int cert_append_info(unsigned char buffer[], unsigned int id, const char *cname, const char time[TIME_BUFFER_SIZE], const char valid[TIME_BUFFER_SIZE], const unsigned char auth_key[SMQV_PKEY_SIZE], const unsigned char token_key[MSS_PKEY_SIZE]);
unsigned int cert_split_info(const unsigned char buffer[], unsigned int *id, char *cname, char time[TIME_BUFFER_SIZE], char valid[TIME_BUFFER_SIZE], unsigned char auth_key[SMQV_PKEY_SIZE], unsigned char token_key[MSS_PKEY_SIZE], unsigned char cert_signature[ECDSA_SIGNATURE_SIZE]);

/*
 *	CSR stands for certificate request, which is sent by the client (or gateway) in order to provide the info needed by the AAAS to generate the certificate.
 *
 *		CSR info:
 *				- id: requester identification
 *				- cname: common name
 *				- time: date on which the csr has been generated
 *				- auth_key: key used in mutual authentication (SMQV)
 *				- token_key: key used to sign access token (MSS)
 *				- csr_signature: CSR signature under token_key
 *
 */
void generate_csr(unsigned int id, char *cname, unsigned char auth_key[SMQV_PKEY_SIZE], unsigned char token_key[MSS_PKEY_SIZE], unsigned char mss_skey[MSS_SKEY_SIZE], char csr[CSR_MAX_SIZE]) {
	// append byte array of (id || cname || time || auth_key || token_key)
	unsigned int index = 0;
	unsigned char buffer[CSR_MAX_SIZE];
	memset(buffer, 0, CSR_MAX_SIZE);
	memset(csr, 0, CSR_MAX_SIZE);
	char time[TIME_BUFFER_SIZE];
	now(&time);
	index += csr_append_info(buffer, id, cname, time, auth_key, token_key);

	// sign (id || cname || time || auth_key || token_key)
	sponge_state sponge;
        unsigned char digest[2 * MSS_SEC_LVL];

        sponge_hash(buffer, index, digest, 2 * MSS_SEC_LVL);
	memcpy(buffer + index, mss_sign(mss_skey, digest), MSS_SIGNATURE_SIZE);
	index += MSS_SIGNATURE_SIZE;

	base64encode(buffer, index, csr, CSR_MAX_SIZE);
}

// read and verify whether the csr's signature is valid. Returns 1 if it is, otherwise 0.
unsigned char read_csr(unsigned int *id, char *cname, char time[TIME_BUFFER_SIZE], unsigned char auth_key[SMQV_PKEY_SIZE], unsigned char token_key[MSS_PKEY_SIZE], unsigned char csr_signature[MSS_SIGNATURE_SIZE], char csr[CSR_MAX_SIZE]) {
	unsigned int index = 0;
	int csr_size = CSR_MAX_SIZE;
	unsigned char buffer[CSR_MAX_SIZE];
	memset(buffer, 0, CSR_MAX_SIZE);
	char t_now[TIME_BUFFER_SIZE];
	now(&t_now);
	base64decode(csr, strlen(csr), buffer, &csr_size);

	csr_split_info(buffer, id, cname, time, auth_key, token_key, csr_signature);

        unsigned char digest[2 * MSS_SEC_LVL];
	index = csr_append_info(buffer, *id, cname, time, auth_key, token_key);
        sponge_hash(buffer, index, digest, 2 * MSS_SEC_LVL);

	// verify [(id || cname || time || auth_key || token_key), csr_signature, token_key]
	return mss_verify(csr_signature, token_key, digest) && compare_dates(time, t_now) != -1;
}

unsigned int csr_append_info(unsigned char buffer[], unsigned int id, const char *cname, const char time[TIME_BUFFER_SIZE], const unsigned char auth_key[SMQV_PKEY_SIZE], const unsigned char token_key[MSS_PKEY_SIZE]) {
	unsigned int index = 0;
	sprintf(buffer, "%u %s", id, cname);
	index += strlen(buffer) + 1;
	memcpy(buffer + index, time, TIME_BUFFER_SIZE);
	index += TIME_BUFFER_SIZE;
	memcpy(buffer + index, auth_key, SMQV_PKEY_SIZE);
	index += SMQV_PKEY_SIZE;
	memcpy(buffer + index, token_key, MSS_PKEY_SIZE);
	index += MSS_PKEY_SIZE;
	return index;
}

unsigned int csr_split_info(const unsigned char buffer[], unsigned int *id, char *cname, char time[TIME_BUFFER_SIZE], unsigned char auth_key[SMQV_PKEY_SIZE], unsigned char token_key[MSS_PKEY_SIZE], unsigned char csr_signature[MSS_SIGNATURE_SIZE]) {
	unsigned int index = 0;
	sscanf(buffer, "%u ", id);
	while(buffer[index++] != ' ');
	strcpy(cname, buffer + index);
	index += strlen(cname) + 1;
	memcpy(time, buffer + index, TIME_BUFFER_SIZE);
	index += TIME_BUFFER_SIZE;
	memcpy(auth_key, buffer + index, SMQV_PKEY_SIZE);
	index += SMQV_PKEY_SIZE;
	memcpy(token_key, buffer + index, MSS_PKEY_SIZE);
	index += MSS_PKEY_SIZE;
	memcpy(csr_signature, buffer + index, MSS_SIGNATURE_SIZE);
	index += MSS_SIGNATURE_SIZE;
	return index;
}

/*
 *		Certificate info:
 *				- id: requester identification
 *				- cname: common name
 *				- time: date on which the certificate has been generated
 *				- valid: date up to the certificate is valid
 *				- auth_key: key used in mutual authentication (SMQV)
 *				- token_key: key used to sign access token (MSS)
 *				- signature: signature under issuer's key
 *
 */
void generate_certificate(const unsigned char csr[CSR_MAX_SIZE], const char valid[TIME_BUFFER_SIZE], const unsigned char ca_skey[ECDSA_SKEY_SIZE], unsigned char certificate[CERTIFICATE_MAX_SIZE]) {
	unsigned int id;
	char cname[CNAME_MAX_SIZE], time[TIME_BUFFER_SIZE];
	unsigned char auth_key[SMQV_PKEY_SIZE], token_key[MSS_PKEY_SIZE], cert_signature[ECDSA_SIGNATURE_SIZE], csr_signature[MSS_SIGNATURE_SIZE];
	unsigned char buffer[CERTIFICATE_MAX_SIZE];
	memset(buffer, 0, CERTIFICATE_MAX_SIZE);

	now(&time);

	if(compare_dates(valid, time) == -1 && read_csr(&id, cname, time, auth_key, token_key, csr_signature, csr)) {
		unsigned int index = 0;

		index += cert_append_info(buffer, id, cname, time, valid, auth_key, token_key);

		unsigned char cert_digest[2 * MSS_SEC_LVL];
        	sponge_hash(buffer, index, cert_digest, 2 * MSS_SEC_LVL);
		ecdsa_sign(ca_skey, cert_digest, cert_signature);
		memcpy(buffer + index, cert_signature, ECDSA_SIGNATURE_SIZE);
		index += ECDSA_SIGNATURE_SIZE;

		base64encode(buffer, index, certificate, CSR_MAX_SIZE);
	}
	else{
		if( compare_dates(valid, time) != -1)
			printf("Authentication ERROR: !(valid > t_now)\n");
		else
			printf("Authentication ERROR: !mss_verify\n");
  }
}

// return 1 if certificate is valid, 0 otherwise
unsigned char read_certificate(unsigned int *id, char *cname, char time[TIME_BUFFER_SIZE], char valid[TIME_BUFFER_SIZE], unsigned char auth_key[SMQV_PKEY_SIZE], unsigned char token_key[MSS_PKEY_SIZE], unsigned char cert_signature[ECDSA_SIGNATURE_SIZE], const unsigned char ca_pkey[ECDSA_PKEY_SIZE], const unsigned char certificate[CERTIFICATE_MAX_SIZE]) {
	unsigned int index = 0;
	int certificate_size = CERTIFICATE_MAX_SIZE;
	unsigned char buffer[CERTIFICATE_MAX_SIZE];
	char t_now[TIME_BUFFER_SIZE];

	now(&t_now);
	memset(buffer, 0, CERTIFICATE_MAX_SIZE);
	base64decode(certificate, strlen(certificate), buffer, &certificate_size);

	cert_split_info(buffer, id, cname, time, valid, auth_key, token_key, cert_signature);

	unsigned char cert_digest[2 * MSS_SEC_LVL];
	index = cert_append_info(buffer, *id, cname, time, valid, auth_key, token_key);
        sponge_hash(buffer, index, cert_digest, 2 * MSS_SEC_LVL);

	// verify [(id || cname || time || valid || auth_key || token_key), csr_signature, token_key]
	return compare_dates(t_now, time) <= 0 && compare_dates(t_now, valid) >= 0 && ecdsa_verify(ca_pkey, cert_digest, cert_signature);
}

unsigned int cert_append_info(unsigned char buffer[], unsigned int id, const char *cname, const char time[TIME_BUFFER_SIZE], const char valid[TIME_BUFFER_SIZE], const unsigned char auth_key[SMQV_PKEY_SIZE], const unsigned char token_key[MSS_PKEY_SIZE]) {
	unsigned int index = 0;
	sprintf(buffer, "%u %s", id, cname);
	index += strlen(buffer) + 1;
	memcpy(buffer + index, time, TIME_BUFFER_SIZE);
	index += TIME_BUFFER_SIZE;
	memcpy(buffer + index, valid, TIME_BUFFER_SIZE);
	index += TIME_BUFFER_SIZE;
	memcpy(buffer + index, auth_key, SMQV_PKEY_SIZE);
	index += SMQV_PKEY_SIZE;
	memcpy(buffer + index, token_key, MSS_PKEY_SIZE);
	index += MSS_PKEY_SIZE;
	return index;
}

unsigned int cert_split_info(const unsigned char buffer[], unsigned int *id, char *cname, char time[TIME_BUFFER_SIZE], char valid[TIME_BUFFER_SIZE], unsigned char auth_key[SMQV_PKEY_SIZE], unsigned char token_key[MSS_PKEY_SIZE], unsigned char cert_signature[ECDSA_SIGNATURE_SIZE]) {
	unsigned int index = 0;
	sscanf(buffer, "%u ", id);
	while(buffer[index++] != ' ');
	strcpy(cname, buffer + index);
	index += strlen(cname) + 1;
	memcpy(time, buffer + index, TIME_BUFFER_SIZE);
	index += TIME_BUFFER_SIZE;
	memcpy(valid, buffer + index, TIME_BUFFER_SIZE);
	index += TIME_BUFFER_SIZE;
	memcpy(auth_key, buffer + index, SMQV_PKEY_SIZE);
	index += SMQV_PKEY_SIZE;
	memcpy(token_key, buffer + index, MSS_PKEY_SIZE);
	index += MSS_PKEY_SIZE;
	memcpy(cert_signature, buffer + index, ECDSA_SIGNATURE_SIZE);
	index += ECDSA_SIGNATURE_SIZE;
	return index;
}

#ifdef CERTIFICATE_SELFTEST

#include <stdlib.h>
#include <time.h>

int main() {
	time_t t;
	srand((unsigned) time(&t));

	unsigned int id = rand(), i;
	char cname[CNAME_MAX_SIZE], time[TIME_BUFFER_SIZE], valid[TIME_BUFFER_SIZE], csr[CSR_MAX_SIZE], csr_cpy[CSR_MAX_SIZE], certificate[CERTIFICATE_MAX_SIZE], certificate_cpy[CERTIFICATE_MAX_SIZE];
	unsigned char auth_key[SMQV_PKEY_SIZE], token_keypair[MSS_SKEY_SIZE + MSS_PKEY_SIZE], token_skey[MSS_SKEY_SIZE], token_pkey[MSS_PKEY_SIZE], csr_signature[MSS_SIGNATURE_SIZE], signature[ECDSA_SIGNATURE_SIZE];

  // valid: 3333XXXXXXXXXX
  now(&valid);
  valid[0] = '3';
  valid[1] = '3';
  valid[2] = '3';
  valid[3] = '3';


	sprintf(cname, "TESTE do CERTIFICATE");

	unsigned char seed[LEN_BYTES(MSS_SEC_LVL)] = {0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F};

	memcpy(token_keypair, mss_keygen(seed), MSS_SKEY_SIZE + MSS_PKEY_SIZE);
	memcpy(token_skey, token_keypair, MSS_SKEY_SIZE);
	memcpy(token_pkey, token_keypair + MSS_SKEY_SIZE, MSS_PKEY_SIZE);

	for(i = 0; i < SMQV_PKEY_SIZE; i++)
		auth_key[i] = rand();

	/**
	 * CSR
	 */
	generate_csr(id, cname, auth_key, token_pkey, token_skey, csr);
	if(read_csr(&id, cname, time, auth_key, token_pkey, csr_signature, csr))
		printf("CSR generation/read - OK\n");
	else
		printf("CSR generation/read - Fail\n");
	printf("\n");

	/**
	 * CERTIFICATE
	 */
	unsigned char ca_skey[ECDSA_SKEY_SIZE], ca_pkey[ECDSA_PKEY_SIZE];

	ecdsa_keygen(ca_skey, ca_pkey);
	generate_certificate(csr, valid, ca_skey, certificate);
	if(read_certificate(&id, cname, time, valid, auth_key, token_pkey, signature, ca_pkey, certificate))
		printf("CERTIFICATE generation/read - OK\n");
	else
		printf("CERTIFICATE generation/read - Fail\n");
	printf("\n");

	return 0;
}

#endif
