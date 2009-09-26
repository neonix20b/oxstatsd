
CFLAGS=-O2 -pipe -fPIC -march=k8 -Wall -I../include -I ../base64/include
CFLAGS_TEST=-O2 -pipe -march=k8 -Wall -I../include
LIBS=-L../base64/lib -lbase64
LIBS_TEST=-L../lib -L../base64/lib -loxdigest -lcrypto -lbase64 -lm

liboxdigest.a: oxdigest.o
	ar rcs ../lib/liboxdigest.a oxdigest.o 

oxdigest.o: oxdigest.c
	gcc -c ${CFLAGS} oxdigest.c -o oxdigest.o ${LIBS}

get: get.c liboxdigest.a
	gcc ${CFLAGS_TEST} get.c -o get ${LIBS_TEST}

test: test.c liboxdigest.a
	gcc ${CFLAGS_TEST} test.c -o test ${LIBS_TEST}


