CC?=gcc
CFLAGS=-std=c99 -Wall -pedantic -Ihashbasedsignature-code/workspace/include -Imicro-ecc -Ilibntru/src
HASHBASEDSIG_RoR_PROJ=hashbasedsignature-code/projects/PC-RAILS-C
HASHBASEDSIG_SRC=hashbasedsignature-code/workspace/src
HASHBASEDSIG_OBJS=bin/ti_aes_128_enc.o bin/mss_aes.o bin/hash.o bin/winternitz.o bin/mss.o bin/keccak.o bin/sponge.o bin/util.o
uECC=micro-ecc
NTRU_SRC_DIR=libntru/src
NTRU_TESTS_DIR=libntru/tests
NTRU_SRC=ntru bitstring encparams hash idxgen key mgf poly rand sha1 sha2
NTRU_TESTS=test_bitstring test_hash test_idxgen test_key test_ntru test_poly test_ntru test_util
NTRU_TESTS_OBJS=bin/test_bitstring.o bin/test_hash.o bin/test_idxgen.o bin/test_key.o bin/test_poly.o bin/test_ntru.o bin/test_util.o
NTRU_OBJS=bin/ntru.o bin/bitstring.o bin/encparams.o bin/hash.o bin/idxgen.o bin/key.o bin/mgf.o bin/poly.o bin/rand.o bin/sha1.o bin/sha2.o $(NTRU_TESTS_OBJS)
ECDSA_OBJS=bin/uECC.o bin/ecdsa.o

all:		certificate ecdsa ntru

ntru:		$(NTRU_SRC_DIR)/ntru.c
		$(foreach src, $(NTRU_SRC), $(CC) $(NTRU_SRC_DIR)/$(src).c -c -o bin/$(src).o $(CFLAGS);)
		$(foreach src, $(NTRU_TESTS), $(CC) $(NTRU_TESTS_DIR)/$(src).c -c -o bin/$(src).o $(CFLAGS);)
		$(CC) $(NTRU_TESTS_DIR)/test.c -o bin/lib$@ $(NTRU_OBJS) $(CFLAGS)
		$(CC) $(HASHBASEDSIG_SRC)/util.c -c -o bin/util.o $(CFLAGS) 
		$(CC) $@.c -o bin/$@ -DNTRU_SELFTEST -DDEBUG $(NTRU_OBJS) bin/util.o $(CFLAGS)

ecdsa:		$(uECC)/uECC.c
		$(CC) $(uECC)/uECC.c -c -o bin/uECC.o $(CFLAGS)
		$(CC) $(uECC)/test/test_ecdsa.c -o bin/uECC bin/uECC.o $(CFLAGS)
		$(CC) $(HASHBASEDSIG_SRC)/util.c -c -o bin/util.o $(CFLAGS) 
		$(CC) $@.c -c -o bin/$@.o bin/uECC.o $(CFLAGS)
		$(CC) $@.c -o bin/$@ -DECDSA_SELFTEST -DDEBUG bin/uECC.o bin/util.o $(CFLAGS)

certificate:	certificate.c
		make ecdsa
		rm -rf $(HASHBASEDSIG_RoR_PROJ)/bin && mkdir $(HASHBASEDSIG_RoR_PROJ)/bin
		$(MAKE) -C $(HASHBASEDSIG_RoR_PROJ) sponge mss
		$(foreach obj, $(HASHBASEDSIG_OBJS), cp $(HASHBASEDSIG_RoR_PROJ)/$(HASHBASEDSIG_SPOGE_MSS_OBJS)/$(obj) $(obj);)
		rm -rf $(HASHBASEDSIG_RoR_PROJ)/bin
		$(CC) cert_time.c -c -o bin/cert_time.o $(CFLAGS)
		$(CC) $@.c -o bin/$@ -DCERTIFICATE_SELFTEST $(HASHBASEDSIG_OBJS) $(ECDSA_OBJS) bin/cert_time.o $(CFLAGS)

clean:		
		rm -rf bin/*
