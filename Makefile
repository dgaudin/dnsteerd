# dnsteerd — DNS-driven first-packet traffic steering daemon
#
# Intégration plateforme via DEUX fichiers locaux OPTIONNELS, git-ignorés dans
# le dépôt public (aucune mention de plateforme dans les sources publiées) :
#   - profile.h   : surcharge des #define C (chemins, table nft…) cf. defaults.h
#   - config.inc  : surcharge des variables Make (PREFIX, NDPI_INC…) ci-dessous
# Absents → défauts publics neutres. Tout reste surchargeable en ligne de
# commande (make PREFIX=... NDPI_INC=...).
-include config.inc

PREFIX ?= /usr/local

CC = gcc
CFLAGS = -O2 -Wall -Wextra -Wno-unused-parameter \
         -I/usr/include/ndpi
LDFLAGS = -lmnl -lnetfilter_queue -lnftables -lnftnl -lndpi

# Tables host de la nDPI installée (si packagées avec les headers). Présentes
# → dns_protocols.inc est régénéré contre la lib RÉELLEMENT liée (zéro drift) ;
# absentes (paquet nDPI standard) → on garde le dns_protocols.inc committé.
NDPI_INC ?= /usr/include/ndpi

TARGET = dnsteerd
SRC = dnsteerd.c
OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OBJ): defaults.h dns_protocols.inc $(wildcard profile.h)

# Régénère seulement si les tables installées existent ET sont plus récentes.
# Écriture atomique : un générateur en échec (tables absentes → 0 proto) NE
# DOIT PAS écraser le fichier committé. mv seulement si génération réussie.
dns_protocols.inc: $(wildcard $(NDPI_INC)/ndpi_content_match.c.inc)
	sh gen_dns_protocols.sh $(NDPI_INC) > $@.tmp && mv $@.tmp $@ || { rm -f $@.tmp; false; }

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 750 $(TARGET) $(DESTDIR)$(PREFIX)/bin/
	install -m 750 m365-sync.sh $(DESTDIR)$(PREFIX)/bin/

.PHONY: all clean install
