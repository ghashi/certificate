#ifndef __NTRU_H_
#define __NTRU_H_

void ntru_keygen(unsigned char *skey, unsigned char *pkey);
void ntru_encryption(const unsigned char *pkey, const char *plaintext, unsigned char *ciphertext);
void ntru_decryption(const unsigned char *skey, const unsigned char *ciphertext, char *plaintext);

#endif // __NTRU_H_
