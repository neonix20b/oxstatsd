
CFLAGS=-O2 -pipe -fPIC -march=k8 -Wall -I../include

libbase64.a: base64.o
	ar rcs ../lib/libbase64.a base64.o 

base64.o: base64.c
	gcc -c ${CFLAGS} base64.c -o base64.o

