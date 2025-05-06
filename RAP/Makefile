
CC=gcc
CFLAGS=-Wall -Wextra -O2 -Iinclude
LIBS=-lpcap -lssl -lcrypto

SRC=$(wildcard src/*.c)
OBJ=$(SRC:.c=.o)

all: rogueap

rogueap: main.o $(OBJ)
	$(CC) -o $@ $^ $(LIBS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

clean:
	rm -f src/*.o *.o rogueap
