
CC=gcc
CFLAGS=-Wall -Wextra -O2 -Iinclude
LIBS=-lpcap -lssl -lcrypto

SRC=$(wildcard src/*.c)
OBJ=$(SRC:.c=.o)

TARGET=RAP

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o *.o $(TARGET)

.PHONY: all clean