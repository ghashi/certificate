CC?=gcc
CFLAGS=-std=c99 -Wall -pedantic -Ihashbasedsignature-code/workspace/include -Imicro-ecc -Ilibntru/src
LFLAGS=-c -fPIC
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
DYN_LIB_OBJS=bin/dyn_bitstring.o bin/dyn_certificate.o bin/dyn_cert_time.o bin/dyn_ecdsa.o bin/dyn_encparams.o bin/dyn_hash.o bin/dyn_idxgen.o bin/dyn_key.o bin/dyn_libntru.o bin/dyn_mgf.o bin/dyn_ntru.o bin/dyn_poly.o bin/dyn_rand.o bin/dyn_sha1.o bin/dyn_sha2.o bin/dyn_uECC.o

all:		certificate ecdsa ntru libs

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

libs:	certificate.c
		make ecdsa
		rm -rf $(HASHBASEDSIG_RoR_PROJ)/bin && mkdir $(HASHBASEDSIG_RoR_PROJ)/bin
		$(MAKE) -C $(HASHBASEDSIG_RoR_PROJ) libs
		cp $(HASHBASEDSIG_RoR_PROJ)/bin/libcrypto.so bin
		rm -rf $(HASHBASEDSIG_RoR_PROJ)/bin
		$(CC) $(LFLAGS) -o bin/dyn_cert_time.o cert_time.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_certificate.o certificate.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_ntru.o ntru.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_ecdsa.o ecdsa.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_uECC.o $(uECC)/uECC.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_libntru.o $(NTRU_SRC_DIR)/ntru.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_bitstring.o $(NTRU_SRC_DIR)/bitstring.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_encparams.o $(NTRU_SRC_DIR)/encparams.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_hash.o $(NTRU_SRC_DIR)/hash.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_idxgen.o $(NTRU_SRC_DIR)/idxgen.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_key.o $(NTRU_SRC_DIR)/key.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_mgf.o $(NTRU_SRC_DIR)/mgf.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_poly.o $(NTRU_SRC_DIR)/poly.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_rand.o $(NTRU_SRC_DIR)/rand.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_sha1.o $(NTRU_SRC_DIR)/sha1.c $(CFLAGS)
		$(CC) $(LFLAGS) -o bin/dyn_sha2.o $(NTRU_SRC_DIR)/sha2.c $(CFLAGS)
		$(CC) -shared -fPIC -Wl,-soname,libcertificate.so -o bin/libcertificate.so $(DYN_LIB_OBJS) -lc

clean:
		rm -rf bin/*
