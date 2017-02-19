CC = gcc
CFLAGS = -m32

all: $(patsubst %.c, %, $(wildcard *.c))

%: %.c Makefile
	$(CC) $(CFLAGS) $< -o $@_32
