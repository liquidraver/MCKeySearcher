CXX = g++

CXX_FLAGS = -std=c++17 -O3 -march=native -mtune=native \
            -fomit-frame-pointer -pthread -DNDEBUG \
            -funroll-loops -fprefetch-loop-arrays \
            -flto -fwhole-program -fuse-linker-plugin \
            -fno-stack-protector -fno-asynchronous-unwind-tables \
            -fno-unwind-tables -fno-ident \
            -mavx2 -mfma -mbmi2 -mpopcnt -mlzcnt \
            -ffast-math -fno-trapping-math -fno-math-errno \
            -fno-signed-zeros -fno-rounding-math -fno-signaling-nans

LIBS = -lsodium -lpthread -lnuma -ldl

CPP_SRC = main.cpp
OBJ_FILES = main.o

TARGET = mckeysearcher

# Performance-optimized build (default)
all: $(TARGET)

# Debug build
debug: CXX_FLAGS = -std=c++17 -g -O0 -DDEBUG -march=native -pthread
debug: $(TARGET)

# Profile-guided optimization build
pgo: CXX_FLAGS += -fprofile-generate
pgo: $(TARGET)
	@echo "Run the program to generate profile data, then run 'make pgo-opt'"

pgo-opt: CXX_FLAGS = -std=c++17 -O3 -march=native -mtune=native \
            -fomit-frame-pointer -pthread -DNDEBUG \
            -funroll-loops -fprefetch-loop-arrays \
            -flto -fwhole-program -fuse-linker-plugin \
            -fno-stack-protector -fno-asynchronous-unwind-tables \
            -fno-unwind-tables -fno-ident \
            -mavx2 -mfma -mbmi2 -mpopcnt -mlzcnt \
            -ffast-math -fno-trapping-math -fno-math-errno \
            -fno-signed-zeros -fno-rounding-math -fno-signaling-nans \
            -fprofile-use -fprofile-correction
pgo-opt: $(TARGET)

$(TARGET): $(OBJ_FILES)
	$(CXX) $(CXX_FLAGS) $(OBJ_FILES) $(LIBS) -o $(TARGET)

main.o: $(CPP_SRC)
	$(CXX) $(CXX_FLAGS) -c $< -o $@

clean:
	rm -f $(OBJ_FILES) $(TARGET) *.o *.gcda *.gcno *.profraw

install-deps:
	sudo apt update
	sudo apt install -y build-essential g++ make
	sudo apt install -y libsodium-dev libnuma-dev

.PHONY: all debug pgo pgo-opt clean install-deps

