# confessions Makefile

CC?=cc
OBJDIR?=obj
BIN=confessions

DESTDIR?=
PREFIX?=/usr/local
INSTALL_DIR=$(PREFIX)/bin

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common
CFLAGS+=-Iinclude
CFLAGS+=-g

SRC=	src/confession.c \
	src/audio.c \
	src/liturgy.c \
	src/ring.c \
	src/tunnel.c

ifeq ("$(SANITIZE)", "1")
	CFLAGS+=-fsanitize=address,undefined
	LDFLAGS+=-fsanitize=address,undefined
endif

ifeq ("$(OSNAME)", "")
OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
endif

ifeq ("$(OSNAME)", "linux")
	LDFLAGS+=-lkyrka
	CFLAGS+=-I/usr/local/include
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
else ifeq ("$(OSNAME)", "windows")
	CFLAGS+=-D_GNU_SOURCE=1 -DPLATFORM_WINDOWS -I$(LIBKYRKA_PATH)/include
	LDFLAGS+=-L$(LIBKYRKA_PATH)/lib -lkyrka -lwsock32 -lws2_32
else
	LDFLAGS+=-lkyrka
	CFLAGS+=-I/usr/local/include
endif

CFLAGS+=$(shell pkg-config --cflags portaudio-2.0)
CFLAGS+=$(shell pkg-config --cflags opus)

LDFLAGS+=$(shell pkg-config --libs portaudio-2.0)
LDFLAGS+=$(shell pkg-config --libs libsodium)
LDFLAGS+=$(shell pkg-config --libs opus)

OBJS=	$(SRC:src/%.c=$(OBJDIR)/%.o)

all: $(BIN)

$(BIN): $(OBJDIR) $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(BIN)

install: $(BIN)
	mkdir -p $(DESTDIR)$(INSTALL_DIR)
	install -m 555 $(BIN) $(DESTDIR)$(INSTALL_DIR)/$(BIN)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(BIN)*

.PHONY: all clean force
