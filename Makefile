CC = g++
CFLAGS = -std=c++14 -O3 -flto -march=native -mtune=native \
         -mavx2 -fomit-frame-pointer -fexceptions -pthread \
         -funroll-loops -fprefetch-loop-arrays \
         -DNDEBUG -fno-stack-protector
LDFLAGS = -lpthread

# Profile-guided optimization flags
PGO_GENERATE = -fprofile-generate
PGO_USE = -fprofile-use -fprofile-correction

LIBSODIUM_DIR = deps/libsodium
ED25519_DIR = deps/ed25519
LIBSODIUM_LIB = $(LIBSODIUM_DIR)/src/libsodium/.libs/libsodium.a
ED25519_LIB = $(ED25519_DIR)/libed25519.a

all: $(LIBSODIUM_LIB) $(ED25519_LIB) findkey

$(LIBSODIUM_LIB):
	mkdir -p deps
	test -d $(LIBSODIUM_DIR) || git clone --branch next https://github.com/jedisct1/libsodium $(LIBSODIUM_DIR)
	cd $(LIBSODIUM_DIR) && ./autogen.sh && ./configure --enable-static --disable-shared && make

$(ED25519_LIB):
	mkdir -p deps
	test -d $(ED25519_DIR) || git clone https://github.com/orlp/ed25519 $(ED25519_DIR)
	cd $(ED25519_DIR)/src && gcc -c add_scalar.c fe.c ge.c key_exchange.c keypair.c sc.c seed.c sha512.c sign.c verify.c
	cd $(ED25519_DIR)/src && ar rcs libed25519.a add_scalar.o fe.o ge.o key_exchange.o keypair.o sc.o seed.o sha512.o sign.o verify.o
	mv $(ED25519_DIR)/src/libed25519.a $(ED25519_DIR)/
	cd $(ED25519_DIR)/src && rm -f *.o

findkey: main.cpp $(LIBSODIUM_LIB) $(ED25519_LIB)
	$(CC) $(CFLAGS) -I$(LIBSODIUM_DIR)/src/libsodium/include -I$(ED25519_DIR) \
	    main.cpp $(LIBSODIUM_LIB) $(ED25519_LIB) $(LDFLAGS) -o findkey

# Profile-guided optimization targets
pgo-generate: CFLAGS += $(PGO_GENERATE)
pgo-generate: main.cpp $(LIBSODIUM_LIB) $(ED25519_LIB)
	$(CC) $(CFLAGS) -I$(LIBSODIUM_DIR)/src/libsodium/include -I$(ED25519_DIR) \
	    main.cpp $(LIBSODIUM_LIB) $(ED25519_LIB) $(LDFLAGS) -o findkey

pgo-use: CFLAGS += $(PGO_USE)
pgo-use: main.cpp $(LIBSODIUM_LIB) $(ED25519_LIB)
	$(CC) $(CFLAGS) -I$(LIBSODIUM_DIR)/src/libsodium/include -I$(ED25519_DIR) \
	    main.cpp $(LIBSODIUM_LIB) $(ED25519_LIB) $(LDFLAGS) -o findkey

clean:
	rm -f findkey
	rm -f *.gcda *.gcno *.gcov
	cd $(LIBSODIUM_DIR) && make clean || true
	cd $(ED25519_DIR) && rm -f libed25519.a || true
