CC = gcc
CFLAGS = -Wall -Werror
OBJ = alps-reg-dump.o

%.o: %.c
	$(CC) -c -o $@ $^ $(CFLAGS)

alps-reg-dump: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(OBJ) alps-reg-dump
