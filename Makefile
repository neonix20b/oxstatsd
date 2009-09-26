CFLAGS=-O2 -Wall -I/usr/include/postgresql-8.3 -Ioxdigest/include
LIBS=-L/usr/lib/postgresql-8.3/lib -Loxdigest/lib -Loxdigest/base64/lib -lpcre -lpq -loxdigest -lbase64 -lcrypto

all:
	gcc -c ${CFLAGS} oxstatsd.c -o oxstatsd.o
	gcc oxstatsd.o -o oxstatsd ${LIBS}
install:
	cp oxstatsd /usr/sbin/oxhosting

