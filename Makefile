CC = gcc
CFLAGS = -Wall -Werror
OBJ = detect-alps.o

%.o: %.c
	$(CC) -c -o $@ $^ $(CFLAGS)

detect-alps: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)
	strip $@

.PHONY: clean

install: detect-alps
	install -d $(DESTDIR)/usr/bin
	install -m 755 detect-alps $(DESTDIR)/usr/bin/

clean:
	rm -f $(OBJ) detect-alps