# confessions Makefile

CC?=cc
OBJDIR?=obj
BIN=confessions
VERSION=$(OBJDIR)/version

DESTDIR?=
PREFIX?=/usr/local
INSTALL_DIR=$(PREFIX)/bin
LIBKYRKA_PATH?=/usr/local

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

CFLAGS+=-I$(LIBKYRKA_PATH)/include
LDFLAGS+=-L$(LIBKYRKA_PATH)/lib -lkyrka

ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
else ifeq ("$(OSNAME)", "windows")
	CFLAGS+=-DPLATFORM_WINDOWS
	LDFLAGS+=-lwsock32 -lws2_32
endif

CFLAGS+=$(shell pkg-config --cflags portaudio-2.0)
CFLAGS+=$(shell pkg-config --cflags opus)

LDFLAGS+=$(shell pkg-config --libs portaudio-2.0)
LDFLAGS+=$(shell pkg-config --libs libsodium)
LDFLAGS+=$(shell pkg-config --libs opus)

OBJS=	$(SRC:src/%.c=$(OBJDIR)/%.o)
OBJS+=	$(OBJDIR)/version.o

all:
	$(MAKE) $(OBJDIR)
	$(MAKE) $(BIN)

$(BIN): $(OBJDIR) $(OBJS) $(VERSION).c
	$(CC) $(OBJS) $(LDFLAGS) -o $(BIN)

install: $(BIN)
	mkdir -p $(DESTDIR)$(INSTALL_DIR)
	install -m 555 $(BIN) $(DESTDIR)$(INSTALL_DIR)/$(BIN)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

src/confessions: $(VERSION).c

$(VERSION).c: force
	@if [ -f RELEASE ]; then \
		printf "const char *confessions_build_rev = \"%s\";\n" \
		    `cat RELEASE` > $(VERSION)_gen; \
	elif [ -d .git ]; then \
		GIT_REVISION=`git rev-parse --short=8 HEAD`; \
		GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`; \
		rm -f $(VERSION)_gen; \
		printf "const char *confessions_build_rev = \"%s-%s\";\n" \
		    $$GIT_BRANCH $$GIT_REVISION > $(VERSION)_gen; \
	else \
		echo "No version information found (no .git or RELEASE)"; \
		exit 1; \
	fi
	@printf "const char *confessions_build_date = \"%s\";\n" \
	    `date +"%Y-%m-%d"` >> $(VERSION)_gen;
	@if [ -f $(VERSION).c ]; then \
		cmp -s $(VERSION)_gen $(VERSION).c; \
		if [ $$? -ne 0 ]; then \
			cp $(VERSION)_gen $(VERSION).c; \
		fi \
	else \
		cp $(VERSION)_gen $(VERSION).c; \
	fi

clean:
	rm -rf $(OBJDIR) $(BIN)*

.PHONY: all clean force
