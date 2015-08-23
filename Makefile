
ifdef WITH_OPENMP
  CFLAGS += -fopenmp -DWITH_OPENMP
  LDFLAGS += -fopenmp
endif

CFLAGS += -std=c99 -O3 -g -Wall -Werror -Wextra -pedantic
LDLIBS += -lcrypto

all: testfastpbkdf2 libfastpbkdf2.a bench benchmulti

testfastpbkdf2: fastpbkdf2.o testfastpbkdf2.o

libfastpbkdf2.a: fastpbkdf2.o
	$(AR) r $@ $^

bench: bench.o fastpbkdf2.o
benchmulti: benchmulti.o fastpbkdf2.o

test: testfastpbkdf2
	./testfastpbkdf2

runbench: bench benchmulti
	./bench
	./benchmulti

clean:
	rm -f *.o libfastpbkdf2.a testfastpbkdf2
