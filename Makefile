
CFLAGS += -std=c99 -O3 -Wall -Werror -Wextra -pedantic
LDLIBS += -lcrypto

all: testfastpbkdf2

testfastpbkdf2: fastpbkdf2.o testfastpbkdf2.o

test: testfastpbkdf2
	./testfastpbkdf2

clean:
	rm *.o testfastpbkdf2
