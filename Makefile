CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
LDLIBS += -lcrypto -lm

passlab: passlab.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f passlab

.PHONY: clean
