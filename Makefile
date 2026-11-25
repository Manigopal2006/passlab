CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_LIBS = -lcrypto
endif
CFLAGS += $(OPENSSL_CFLAGS)
LDLIBS += $(OPENSSL_LIBS) -lm

passlab: passlab.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f passlab

.PHONY: clean
