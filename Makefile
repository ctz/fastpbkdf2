
ifdef WITH_OPENMP
  CFLAGS += -fopenmp -DWITH_OPENMP
  LDFLAGS += -fopenmp
endif

CFLAGS += -std=c99 -O3 -g -Wall -Werror -Wextra -pedantic -march=native
LDLIBS += -lcrypto
YASM = yasm -f x64 -f elf64 -X gnu -g dwarf2 -D LINUX

OBJS = fastpbkdf2.o sha256_sse4.o sha256_avx1.o

all: testfastpbkdf2 libfastpbkdf2.a bench benchmulti

testfastpbkdf2: $(OBJS) testfastpbkdf2.o

%.o: %.asm
	$(YASM) -o $@ $^

libfastpbkdf2.a: $(OBJS)
	$(AR) r $@ $^

bench: bench.o $(OBJS)
benchmulti: benchmulti.o $(OBJS)

test: testfastpbkdf2
	./testfastpbkdf2

runbench: bench benchmulti
	./bench
	./benchmulti

clean:
	rm -f *.o libfastpbkdf2.a testfastpbkdf2 bench benchmulti
