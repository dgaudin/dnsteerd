# dnsteerd — DNS-driven first-packet traffic steering daemon
#
# L'intégration plateforme se fait via un fichier local optionnel
# « profile.h » (git-ignoré dans le dépôt public) : présent, ses #define
# priment sur defaults.h. Aucun flag de build à passer.

PREFIX ?= /usr/local

CC = gcc
CFLAGS = -O2 -Wall -Wextra -Wno-unused-parameter \
         -I/usr/include/ndpi
LDFLAGS = -lmnl -lnetfilter_queue -lnftables -lnftnl -lndpi

TARGET = dnsteerd
SRC = dnsteerd.c
OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OBJ): defaults.h $(wildcard profile.h)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 750 $(TARGET) $(DESTDIR)$(PREFIX)/bin/

.PHONY: all clean install
