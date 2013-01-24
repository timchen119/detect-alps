CC = gcc
CFLAGS = -Wall -Werror
OBJ = detect-alps.o

%.o: %.c
	$(CC) -c -o $@ $^ $(CFLAGS)

detect-alps: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(OBJ) detect-alps