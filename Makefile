CC = g++
CFLAGS = -std=c++14 -O3 -flto -march=native -mtune=native \
         -mavx2 -fomit-frame-pointer -fexceptions -pthread \
         -funroll-loops -fprefetch-loop-arrays \
         -DNDEBUG -fno-stack-protector -msha
LDFLAGS = -lpthread -lssl -lcrypto

# Profile-guided optimization flags
PGO_GENERATE = -fprofile-generate
PGO_USE = -fprofile-use -fprofile-correction

all: mckeysearcher

mckeysearcher: main.cpp
	$(CC) $(CFLAGS) main.cpp $(LDFLAGS) -o mckeysearcher

# Profile-guided optimization targets
pgo-generate: CFLAGS += $(PGO_GENERATE)
pgo-generate: main.cpp
	$(CC) $(CFLAGS) main.cpp $(LDFLAGS) -o mckeysearcher

pgo-use: CFLAGS += $(PGO_USE)
pgo-use: main.cpp
	$(CC) $(CFLAGS) main.cpp $(LDFLAGS) -o mckeysearcher

clean:
	rm -f mckeysearcher
	rm -f *.gcda *.gcno *.gcov
