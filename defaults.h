/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * dnsteerd — défauts de compilation.
 *
 * Une intégration plateforme peut surcharger n'importe laquelle de ces
 * valeurs dans un fichier local OPTIONNEL « profile.h » (git-ignoré dans
 * le dépôt public) : s'il est présent, ses #define priment. Aucune
 * configuration runtime.
 */
#ifndef DNSTEERD_DEFAULTS_H
#define DNSTEERD_DEFAULTS_H

#ifndef RUNTIME_DIR
#define RUNTIME_DIR         "/run/dnsteerd"
#endif

#ifndef PIDFILE
#define PIDFILE             RUNTIME_DIR "/dnsteerd.pid"
#endif

/* Liste des protocoles applicatifs (JSON), écrite par `dnsteerd boot`. */
#ifndef PROTOS_JSON_PATH
#define PROTOS_JSON_PATH    RUNTIME_DIR "/protocols.json"
#endif

/* Protocoles custom nDPI (format ndpi_load_protocols_file). */
#ifndef CUSTOM_PROTOS_PATH
#define CUSTOM_PROTOS_PATH  "/etc/dnsteerd/custom_protocols.txt"
#endif

/* Répertoire « conf.d » de protocoles custom additionnels, chargés EN PLUS
 * de CUSTOM_PROTOS_PATH (chaque *.txt). Permet à une source auto-synchronisée
 * (ex. domaines Microsoft 365) de vivre dans son propre fichier sans toucher
 * au custom_protocols principal — absent = simplement ignoré. */
#ifndef CUSTOM_PROTOS_DIR
#define CUSTOM_PROTOS_DIR   "/etc/dnsteerd/protocols.d"
#endif

/* Table nftables hébergeant les sets ndpi_v4_<id>. Par défaut une table
 * dédiée, créée par `dnsteerd boot` ; une intégration peut pointer la
 * table existante de son pare-feu. */
#ifndef NFT_TABLE_NAME
#define NFT_TABLE_NAME      "dnsteerd"
#endif

/* Forme libnftables ("inet <nom>") ; libnftnl passe famille et nom à part. */
#ifndef NFT_TABLE
#define NFT_TABLE           "inet " NFT_TABLE_NAME
#endif

/* IPv6 : sets ndpi_v6_<id>, injection des AAAA et des ipv6hint (HTTPS RR).
 * Mettre à 0 pour une plateforme sans IPv6 (pas de sets v6 au boot,
 * enregistrements v6 ignorés). */
#ifndef DNSTEERD_IPV6
#define DNSTEERD_IPV6       1
#endif

#endif /* DNSTEERD_DEFAULTS_H */
