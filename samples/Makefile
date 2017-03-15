CC = gcc
CFLAGS_32 = -m32 -lm
CFLAGS_64 = -m64 -lm

all: $(patsubst %.c, %, $(wildcard *.c))

clear:
	rm bin/*

%: %.c Makefile
	$(CC) $< -o bin/$@_32 $(CFLAGS_32)
	$(CC) $< -o bin/$@_64 $(CFLAGS_64)
