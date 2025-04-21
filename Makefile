CC = gcc
CFLAGS = -g

dhcp: dhcp.c
	$(CC) -o $@.out $< $(CFLAGS)

