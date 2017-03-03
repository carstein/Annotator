CC = gcc
CFLAGS_32 = -m32
CFLAGS_64 = -m64

all: $(patsubst %.c, %, $(wildcard *.c))

%: %.c Makefile
	$(CC) $(CFLAGS_32) $< -o bin/$@_32
	$(CC) $(CFLAGS_64) $< -o bin/$@_64
