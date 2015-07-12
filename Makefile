
CFLAGS += -std=c99 -O3 -Wall -Werror -Wextra -pedantic
LDLIBS += -lcrypto

all: testfastpbkdf2 bench

testfastpbkdf2: fastpbkdf2.o testfastpbkdf2.o

bench: bench.o fastpbkdf2.o

test: testfastpbkdf2
	./testfastpbkdf2

clean:
	rm *.o testfastpbkdf2
