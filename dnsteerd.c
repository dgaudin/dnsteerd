/*
 * dnsteerd — DNS-driven first-packet traffic steering daemon
 *
 * Modes :
 *   boot     — crée les sets nftables ndpi_v4_<id> (+ ndpi_v6_<id> si
 *              DNSTEERD_IPV6) pour chaque protocole applicatif nDPI
 *   daemon   — capture DNS via NFQUEUE, classifie avec nDPI,
 *              injecte les IPs résolues dans les sets avec TTL
 *   list     — affiche les protocoles applicatifs (debug)
 *   sets / set-elements — état des sets (JSON, ou texte avec -t)
 *
 * NFQUEUE 200 (une seule queue). Le daemon crée lui-même sa table
 * d'interception `inet dnsteerd_filter` (priority -175, `bypass` = fail-open) :
 *   PREROUTING  : udp sport 53 (réponses) + udp dport 53 (requêtes transit)
 *   OUTPUT      : udp dport 53 (requêtes émises par l'hôte, ex. resolver local)
 * La famille inet couvre le DNS transporté en IPv4 ET en IPv6.
 *
 * Principe :
 *   1. Réponse DNS arrive en PREROUTING → NFQUEUE 200
 *   2. nDPI classifie le domaine (host_server_name) → app_protocol
 *   3. nDPI parse la réponse → rsp_addr[] (A/AAAA) + TTL ; dnsteerd parse
 *      lui-même les HTTPS RR type 65 (ipv4hint/ipv6hint, RFC 9460)
 *   4. IPs injectées dans ndpi_v4_<app_id> / ndpi_v6_<app_id> via libnftnl
 *      (un batch transactionnel, ACK sur le dernier message)
 *   5. Verdict NF_ACCEPT → le paquet continue
 *   6. Premier SYN vers l'IP → la règle de policy routing de l'hôte
 *      matche le set → routage (le marquage est hors périmètre du daemon)
 *
 * Protocoles custom :
 *   CUSTOM_PROTOS_PATH selon profil de build (format ndpi_load_protocols_file)
 *
 * Copyright (C) 2026 Didier Gaudin <didier.gaudin@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <time.h>

/* Netfilter / libmnl */
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

/* libnftables (modes boot/sets/set-elements uniquement) */
#include <nftables/libnftables.h>

/* libnftnl + nf_tables : chemin chaud d'injection (perf, anti-latence DNS)
 * + lecture des sets (modes sets/set-elements) : un dump netlink ciblé coûte
 * ~1 ms là où libnftables 0.9.8 reconstruit son cache du ruleset COMPLET à
 * chaque `list set` (∝ taille du firewall ; N+1 sur le mode sets = 20 s
 * mesurées sur box dev). */
#include <linux/netfilter/nf_tables.h>
#include <libnftnl/set.h>
#include <libnftnl/common.h>

/* nDPI 5.0 */
#include <ndpi_main.h>
#include <ndpi_protocol_ids.h>

/* ================================================================
 * Configuration (compilation uniquement, aucune conf runtime)
 *
 * Défauts neutres dans defaults.h ; une intégration plateforme peut les
 * surcharger via un fichier local OPTIONNEL « profile.h » (git-ignoré
 * dans le dépôt public — ses valeurs priment si le fichier est présent).
 * ================================================================ */
#if defined(__has_include)
# if __has_include("profile.h")
#  include "profile.h"
# endif
#endif
#include "defaults.h"

#define QUEUE_NUM           200
#define SET_V4              "ndpi_v4_"
#define SET_V6              "ndpi_v6_"   /* utilisés si DNSTEERD_IPV6 (cf. defaults.h) */
#define MAX_PROTOS          512
#define MIN_TTL             60      /* TTL plancher (secondes) */
#define MAX_TTL             86400   /* TTL plafond  (24 h) */

/* Table de flows DNS (corrélation requête↔réponse) */
#define FLOW_HASH_ROOTS     1024    /* racines d'arbres tsearch (cf. ndpiReader num_roots) */
#define MAX_DNS_FLOWS       8192    /* plafond d'entrées (borne mémoire / anti-flood) */
#define FLOW_IDLE_SEC       10      /* une transaction DNS vit au plus quelques secondes */
#define FLOW_SWEEP_SEC      2       /* période de balayage d'expiration */
#define EXPIRE_BATCH        2048    /* max entrées collectées par balayage */

/* ================================================================
 * Globals
 * ================================================================ */
static volatile sig_atomic_t keep_running = 1;
static struct nft_ctx *nft = NULL;
static struct ndpi_detection_module_struct *ndpi_mod = NULL;

/* Table id → set existant (lookup O(1) par ID) */
#define PROTO_TABLE_SIZE 1024
static int proto_has_set[PROTO_TABLE_SIZE];

/* Socket netlink PERSISTANT pour l'injection des éléments (libnftnl).
 * Évite le parse flex/bison de libnftables à chaque réponse DNS → µs au lieu
 * de ms sur le chemin critique inject-avant-verdict. */
static struct mnl_socket *nft_nl = NULL;
static uint32_t           nft_portid = 0;
static uint32_t           nft_seq = 0;

/* Table de flows DNS : tableau de racines d'arbres tsearch indexées par hashval */
static void   *flow_roots[FLOW_HASH_ROOTS];
static int     g_flow_count = 0;
static time_t  g_last_sweep = 0;

/* ================================================================
 * Helpers
 * ================================================================ */
static void sig_handler(int sig)
{
    (void)sig;
    keep_running = 0;
}

static void write_pidfile(void)
{
    mkdir(RUNTIME_DIR, 0755);           /* idempotent ; EEXIST = cas nominal */
    FILE *f = fopen(PIDFILE, "w");
    if (!f) {
        syslog(LOG_WARNING, "pidfile %s: %s", PIDFILE, strerror(errno));
        return;
    }
    fprintf(f, "%d\n", getpid());
    fclose(f);
}

/* ================================================================
 * Initialisation nDPI
 * ================================================================ */
static struct ndpi_detection_module_struct *init_ndpi(void)
{
    struct ndpi_detection_module_struct *ctx = ndpi_init_detection_module(NULL);
    if (!ctx) {
        fprintf(stderr, "ndpi_init_detection_module() failed\n");
        return NULL;
    }

    /*
     * dns.subclassification : désactivé par défaut en 5.0.3.
     * Nécessaire pour obtenir DNS.Netflix, DNS.YouTube, etc.
     * au lieu de juste DNS.
     */
    ndpi_set_config(ctx, "dns", "subclassification", "enable");

    /*
     * dns.process_response : activé par défaut, mais on s'assure.
     * Remplit flow->protos.dns.rsp_addr[] avec les IPs A/AAAA.
     */
    ndpi_set_config(ctx, "dns", "process_response", "enable");

    /*
     * Protocoles custom utilisateur.
     * Format : host:"*.example.com",MyProto@Streaming
     */
    if (access(CUSTOM_PROTOS_PATH, F_OK) == 0) {
        ndpi_load_protocols_file(ctx, CUSTOM_PROTOS_PATH);
    }

    /* Compilation des automates Aho-Corasick */
    ndpi_finalize_initialization(ctx);

    return ctx;
}

/* ================================================================
 * Injection des IPs dans les sets
 * ================================================================ */
/* Ouvre le socket netlink persistant dédié à l'injection (libnftnl). */
static int nft_open(void)
{
    nft_nl = mnl_socket_open(NETLINK_NETFILTER);
    if (!nft_nl) return -1;
    if (mnl_socket_bind(nft_nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        mnl_socket_close(nft_nl); nft_nl = NULL; return -1;
    }
    nft_portid = mnl_socket_get_portid(nft_nl);
    /* timeout de réception : ne jamais bloquer le daemon si le noyau ne
     * répond pas. Le commit local d'un setelem est sub-milliseconde : au-delà
     * de 200 ms c'est une anomalie — mono-thread, chaque ms passée ici gèle
     * tout le DNS du boîtier, autant rendre la main vite. */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
    setsockopt(mnl_socket_get_fd(nft_nl), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    nft_seq = (uint32_t)time(NULL);
    return 0;
}

static void nft_close(void)
{
    if (nft_nl) { mnl_socket_close(nft_nl); nft_nl = NULL; }
}

/* ---- Lecture des sets en netlink bas niveau (modes sets/set-elements).
 * Un dump GETSET/GETSETELEM ciblé ≈ 1 ms, indépendant de la taille du
 * ruleset — là où libnftables (0.9.8) reconstruisait son cache du firewall
 * COMPLET à chaque `list set` (mode `sets` en N+1 : 20 s sur box dev). ---- */

/* Contexte du dump d'éléments : impression (out!=NULL) et/ou comptage.
 * text=0 → JSON (défaut, consommé par l'UI) ; text=1 → liste lisible. */
struct elem_dump {
    FILE *out;
    int   text;
    int   first;
    int   count;
};

static int set_elems_cb(const struct nlmsghdr *nlh, void *data)
{
    struct elem_dump *c = data;
    struct nftnl_set *s = nftnl_set_alloc();
    if (!s)
        return MNL_CB_OK;
    if (nftnl_set_elems_nlmsg_parse(nlh, s) == 0) {
        struct nftnl_set_elems_iter *it = nftnl_set_elems_iter_create(s);
        if (it) {
            struct nftnl_set_elem *e;
            while ((e = nftnl_set_elems_iter_next(it)) != NULL) {
                uint32_t klen = 0;
                const void *key = nftnl_set_elem_get(e, NFTNL_SET_ELEM_KEY, &klen);
                if (!key || (klen != 4 && klen != 16))
                    continue;                  /* clés ipv4_addr/ipv6_addr */
                if (c->out) {
                    uint64_t tmo = nftnl_set_elem_is_set(e, NFTNL_SET_ELEM_TIMEOUT) ?
                        nftnl_set_elem_get_u64(e, NFTNL_SET_ELEM_TIMEOUT) : 0;
                    uint64_t exp = nftnl_set_elem_is_set(e, NFTNL_SET_ELEM_EXPIRATION) ?
                        nftnl_set_elem_get_u64(e, NFTNL_SET_ELEM_EXPIRATION) : 0;
                    char ip[INET6_ADDRSTRLEN];
                    inet_ntop(klen == 4 ? AF_INET : AF_INET6, key, ip, sizeof ip);
                    if (c->text)
                        fprintf(c->out, "\t%-15s  timeout %llus  expires %llus\n",
                                ip,
                                (unsigned long long)(tmo / 1000), /* ms → s */
                                (unsigned long long)(exp / 1000));
                    else
                        fprintf(c->out, "%s{\"ip\":\"%s\",\"timeout\":%llu,\"expires\":%llu}",
                                c->first ? "" : ",", ip,
                                (unsigned long long)(tmo / 1000),
                                (unsigned long long)(exp / 1000));
                    c->first = 0;
                }
                c->count++;
            }
            nftnl_set_elems_iter_destroy(it);
        }
    }
    nftnl_set_free(s);
    return MNL_CB_OK;
}

/* Dump des éléments de <prefix><id> sur le socket persistant. Set absent →
 * NACK ENOENT, traité comme vide (count=0). 0 = OK, -1 = erreur. */
static int dump_set_elems(const char *prefix, int id, struct elem_dump *c)
{
    char name[64];
    snprintf(name, sizeof name, "%s%d", prefix, id);

    struct nftnl_set *s = nftnl_set_alloc();
    if (!s)
        return -1;
    nftnl_set_set_str(s, NFTNL_SET_TABLE, NFT_TABLE_NAME);
    nftnl_set_set_str(s, NFTNL_SET_NAME, name);

    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq = nft_seq++;
    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETSETELEM,
                                                 NFPROTO_INET, NLM_F_DUMP, seq);
    nftnl_set_elems_nlmsg_build_payload(nlh, s);
    nftnl_set_free(s);

    if (mnl_socket_sendto(nft_nl, nlh, nlh->nlmsg_len) < 0)
        return -1;

    char rbuf[MNL_SOCKET_BUFFER_SIZE];
    int ret;
    while ((ret = mnl_socket_recvfrom(nft_nl, rbuf, sizeof rbuf)) > 0) {
        ret = mnl_cb_run(rbuf, ret, seq, nft_portid, set_elems_cb, c);
        if (ret <= 0)
            break;                  /* NLMSG_DONE ou erreur (ENOENT = vide) */
    }
    return (ret == -1 && errno != ENOENT) ? -1 : 0;
}

/* Collecte les id des sets ndpi_v4_* de la table (dump GETSET). */
struct ids_collect { int *ids; int *nids; int max; };

static int set_list_cb(const struct nlmsghdr *nlh, void *data)
{
    struct ids_collect *c = data;
    struct nftnl_set *s = nftnl_set_alloc();
    if (!s)
        return MNL_CB_OK;
    if (nftnl_set_nlmsg_parse(nlh, s) == 0) {
        const char *table = nftnl_set_get_str(s, NFTNL_SET_TABLE);
        const char *name  = nftnl_set_get_str(s, NFTNL_SET_NAME);
        if (table && strcmp(table, NFT_TABLE_NAME) == 0 &&
            name && strncmp(name, SET_V4, sizeof(SET_V4) - 1) == 0) {
            int id = atoi(name + sizeof(SET_V4) - 1);
            if (id > 0 && id < PROTO_TABLE_SIZE && *c->nids < c->max)
                c->ids[(*c->nids)++] = id;
        }
    }
    nftnl_set_free(s);
    return MNL_CB_OK;
}

static int collect_set_ids(int *ids, int *nids, int max)
{
    struct nftnl_set *s = nftnl_set_alloc();
    if (!s)
        return -1;
    nftnl_set_set_str(s, NFTNL_SET_TABLE, NFT_TABLE_NAME);

    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq = nft_seq++;
    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETSET,
                                                 NFPROTO_INET, NLM_F_DUMP, seq);
    nftnl_set_nlmsg_build_payload(nlh, s);
    nftnl_set_free(s);

    if (mnl_socket_sendto(nft_nl, nlh, nlh->nlmsg_len) < 0)
        return -1;

    struct ids_collect c = { ids, nids, max };
    char rbuf[MNL_SOCKET_BUFFER_SIZE];
    int ret;
    while ((ret = mnl_socket_recvfrom(nft_nl, rbuf, sizeof rbuf)) > 0) {
        ret = mnl_cb_run(rbuf, ret, seq, nft_portid, set_list_cb, &c);
        if (ret <= 0)
            break;
    }
    return (ret == -1) ? -1 : 0;
}

/* Ajoute une adresse (4 ou 16 octets, ordre réseau) au set d'injection
 * `<prefix><app_id>`, en allouant le set au premier élément. TTL borné
 * [MIN_TTL, MAX_TTL]. 0 = OK. */
static int set_add_elem(struct nftnl_set **ps, u_int16_t app_id,
                        const char *prefix, const void *ip, int iplen,
                        u_int32_t ttl)
{
    if (ttl < MIN_TTL) ttl = MIN_TTL;
    if (ttl > MAX_TTL) ttl = MAX_TTL;

    if (!*ps) {
        *ps = nftnl_set_alloc();
        if (!*ps)
            return -1;
        char name[64];
        snprintf(name, sizeof name, "%s%u", prefix, app_id);
        nftnl_set_set_str(*ps, NFTNL_SET_TABLE, NFT_TABLE_NAME);
        nftnl_set_set_str(*ps, NFTNL_SET_NAME, name);
        nftnl_set_set_u32(*ps, NFTNL_SET_FAMILY, NFPROTO_INET);
    }
    struct nftnl_set_elem *e = nftnl_set_elem_alloc();
    if (!e)
        return -1;
    nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, ip, (uint32_t)iplen);
    nftnl_set_elem_set_u64(e, NFTNL_SET_ELEM_TIMEOUT,
                           (uint64_t)ttl * 1000);                 /* ms */
    nftnl_set_elem_add(*ps, e);
    return 0;
}

/* Commit des éléments v4/v6 construits : UN batch
 * BEGIN | NEWSETELEM(v4) [| NEWSETELEM(v6)] | END sur le socket persistant.
 * Le batch nf_tables est TRANSACTIONNEL : un seul NLM_F_ACK, posé sur le
 * DERNIER message, suffit — le kernel n'émet les ACK qu'après le commit (ou
 * l'abort) de la transaction entière. Demander un ACK par message créerait
 * une course (ACK surnuméraire consommé par l'injection suivante comme sa
 * propre confirmation). Attend l'ACK AVANT de rendre la main → sets peuplés
 * avant le verdict. Consomme s4/s6 ; kind4/kind6 = libellés de log. */
static void inject_commit(u_int16_t app_id, struct nftnl_set *s4, int c4,
                          struct nftnl_set *s6, int c6, const char *host,
                          const char *kind4, const char *kind6)
{
    /* Retours de batch_next contrôlés par principe : la borne réelle est en
     * amont (≤16 adresses nDPI / hints courts → ~2-4 Ko, marge ×2 minimum
     * dans le buffer) ; si elle sautait, on jette le batch plutôt que
     * d'envoyer un message tronqué (best-effort, le DNS reste fail-open). */
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct mnl_nlmsg_batch *b = mnl_nlmsg_batch_start(buf, sizeof buf);
    uint32_t ack_seq = 0;
    int ok;

    nftnl_batch_begin(mnl_nlmsg_batch_current(b), nft_seq++);
    ok = mnl_nlmsg_batch_next(b);

    if (ok && s4) {
        if (!s6) ack_seq = nft_seq;            /* dernier message → ACK */
        struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(b),
            NFT_MSG_NEWSETELEM, NFPROTO_INET,
            NLM_F_CREATE | (s6 ? 0 : NLM_F_ACK), nft_seq++);
        nftnl_set_elems_nlmsg_build_payload(nlh, s4);
        ok = mnl_nlmsg_batch_next(b);
    }
    if (ok && s6) {
        ack_seq = nft_seq;
        struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(b),
            NFT_MSG_NEWSETELEM, NFPROTO_INET,
            NLM_F_CREATE | NLM_F_ACK, nft_seq++);
        nftnl_set_elems_nlmsg_build_payload(nlh, s6);
        ok = mnl_nlmsg_batch_next(b);
    }
    if (ok) {
        nftnl_batch_end(mnl_nlmsg_batch_current(b), nft_seq++);
        ok = mnl_nlmsg_batch_next(b);
    }
    if (!ok) {
        syslog(LOG_ERR, "nft setelem: batch overflow (%d+%d elems)", c4, c6);
        mnl_nlmsg_batch_stop(b);
        if (s4) nftnl_set_free(s4);
        if (s6) nftnl_set_free(s6);
        return;
    }

    int rc = mnl_socket_sendto(nft_nl, mnl_nlmsg_batch_head(b),
                               mnl_nlmsg_batch_size(b));
    mnl_nlmsg_batch_stop(b);
    if (s4) nftnl_set_free(s4);
    if (s6) nftnl_set_free(s6);

    if (rc < 0) {
        syslog(LOG_ERR, "nft setelem send: %s", strerror(errno));
        return;
    }

    /* Attendre l'ACK = commit (ordre critique AVANT le verdict), en validant
     * son seq : après un timeout passé, un ACK TARDIF peut traîner dans le
     * socket — sans ce contrôle il serait pris pour la confirmation de CE
     * commit, relâchant le verdict avant l'insertion réelle. */
    char rbuf[MNL_SOCKET_BUFFER_SIZE];
    int ret;
    for (;;) {
        ret = mnl_socket_recvfrom(nft_nl, rbuf, sizeof rbuf);
        if (ret <= 0)
            break;                      /* timeout (200 ms) ou erreur socket */
        ret = mnl_cb_run(rbuf, ret, ack_seq, nft_portid, NULL, NULL);
        if (ret == -1 && errno == EPROTO)
            continue;                   /* seq étranger = ACK résiduel : ignorer */
        break;                          /* MNL_CB_STOP = ACK ok ; -1 = NACK */
    }
    if (ret == -1) {
        syslog(LOG_WARNING, "%s → ndpi %u : nft setelem: %s",
               host, app_id, strerror(errno));
    } else if (c4 && c6) {
        syslog(LOG_INFO, "%s → ndpi %u : %d %s + %d %s",
               host, app_id, c4, kind4, c6, kind6);
    } else {
        syslog(LOG_INFO, "%s → ndpi %u : %d %s",
               host, app_id, c6 ? c6 : c4, c6 ? kind6 : kind4);
    }

    /* Drainer d'éventuels ACK résiduels (non bloquant) → socket propre. */
    int fd = mnl_socket_get_fd(nft_nl);
    char dr[256];
    while (recv(fd, dr, sizeof dr, MSG_DONTWAIT) > 0) { }
}

/* Injecte les A — et les AAAA si DNSTEERD_IPV6 — d'une réponse parsée
 * par nDPI. */
static void inject_ips(u_int16_t app_id, struct ndpi_flow_struct *flow)
{
    int n = flow->protos.dns.num_rsp_addr;
    if (n <= 0 || !nft_nl)
        return;

    struct nftnl_set *s4 = NULL, *s6 = NULL;
    int c4 = 0, c6 = 0;

    for (int i = 0; i < n && i < MAX_NUM_DNS_RSP_ADDRESSES; i++) {
        u_int32_t ttl = flow->protos.dns.rsp_addr_ttl[i];
        if (flow->protos.dns.is_rsp_addr_ipv6[i]) {
            if (DNSTEERD_IPV6 &&
                set_add_elem(&s6, app_id, SET_V6,
                             &flow->protos.dns.rsp_addr[i].ipv6, 16, ttl) == 0)
                c6++;
        } else {
            if (set_add_elem(&s4, app_id, SET_V4,
                             &flow->protos.dns.rsp_addr[i].ipv4, 4, ttl) == 0)
                c4++;
        }
    }

    if (!s4 && !s6)
        return;
    inject_commit(app_id, s4, c4, s6, c6, flow->host_server_name, "A", "AAAA");
}

/* ---- HTTPS RR (type 65, RFC 9460) ----
 * nDPI ne décode pas les RDATA SVCB : or les SvcParams `ipv4hint` (clé 4)
 * livrent des adresses SANS requête A — un client peut s'y connecter
 * directement et passer sous le radar des sets. On parcourt donc la
 * section answers nous-mêmes et on injecte les hints comme des A
 * (toujours AVANT le verdict). Parsing défensif : données réseau. */

/* Avance après un nom DNS (labels / pointeur de compression 0xC0).
 * Retourne le nouvel offset, ou -1 si malformé. */
static int dns_skip_name(const unsigned char *msg, int len, int off)
{
    while (off < len) {
        unsigned int l = msg[off];
        if (l == 0)
            return off + 1;
        if ((l & 0xC0) == 0xC0)                 /* pointeur : 2 octets, fin */
            return (off + 2 <= len) ? off + 2 : -1;
        if ((l & 0xC0) != 0)
            return -1;                          /* 0x40/0x80 : réservés */
        off += 1 + (int)l;
    }
    return -1;
}

static void svcb_inject_hints(u_int16_t app_id, const char *host,
                              const unsigned char *msg, int len)
{
    if (len < 12 || !nft_nl)
        return;
    int qd = (msg[4] << 8) | msg[5];
    int an = (msg[6] << 8) | msg[7];
    if (an <= 0)
        return;

    int off = 12;
    for (int i = 0; i < qd; i++) {              /* sauter les questions */
        off = dns_skip_name(msg, len, off);
        if (off < 0 || off + 4 > len)
            return;
        off += 4;                               /* qtype + qclass */
    }

    struct nftnl_set *s4 = NULL, *s6 = NULL;
    int c4 = 0, c6 = 0;

    for (int i = 0; i < an; i++) {
        off = dns_skip_name(msg, len, off);
        if (off < 0 || off + 10 > len)
            break;
        unsigned int type  = ((unsigned int)msg[off] << 8) | msg[off + 1];
        u_int32_t    ttl   = ((u_int32_t)msg[off + 4] << 24) |
                             ((u_int32_t)msg[off + 5] << 16) |
                             ((u_int32_t)msg[off + 6] << 8)  |
                              (u_int32_t)msg[off + 7];
        int          rdlen = ((int)msg[off + 8] << 8) | msg[off + 9];
        off += 10;
        if (rdlen < 0 || off + rdlen > len)
            break;

        if (type == 65 && rdlen >= 3) {         /* HTTPS RR */
            int rend = off + rdlen;
            int r = off;
            unsigned int prio = ((unsigned int)msg[r] << 8) | msg[r + 1];
            r += 2;
            r = dns_skip_name(msg, rend, r);    /* TargetName (non comprimé) */
            /* prio 0 = AliasMode : pas de SvcParams à lire */
            while (prio > 0 && r >= 0 && r + 4 <= rend) {
                unsigned int k    = ((unsigned int)msg[r] << 8) | msg[r + 1];
                int          vlen = ((int)msg[r + 2] << 8) | msg[r + 3];
                r += 4;
                if (vlen < 0 || r + vlen > rend)
                    break;
                if (k == 4) {                   /* ipv4hint : n × 4 octets */
                    for (int o = 0; o + 4 <= vlen; o += 4)
                        if (set_add_elem(&s4, app_id, SET_V4,
                                         msg + r + o, 4, ttl) == 0)
                            c4++;
                } else if (k == 6 && DNSTEERD_IPV6) {  /* ipv6hint : n × 16 */
                    for (int o = 0; o + 16 <= vlen; o += 16)
                        if (set_add_elem(&s6, app_id, SET_V6,
                                         msg + r + o, 16, ttl) == 0)
                            c6++;
                }
                r += vlen;
            }
        }
        off += rdlen;
    }

    if (s4 || s6)
        inject_commit(app_id, s4, c4, s6, c6, host, "ipv4hint", "ipv6hint");
}

/* ================================================================
 * Table de flows DNS (corrélation requête↔réponse via nDPI)
 *
 * Indispensable : la classification applicative vient du NOM de la
 * REQUÊTE (ex. update.microsoft.com → WindowsUpdate), tandis que les IP
 * arrivent dans la RÉPONSE, souvent sous un CNAME générique
 * (…trafficmanager.net) qui ne matche aucun protocole. Il faut donc
 * passer le MÊME ndpi_flow_struct pour la requête puis la réponse.
 *
 * Clé et appariement bidirectionnel calqués sur ndpiReader :
 *   hashval = l4proto + Σ(octets IP src+dst) + sport + dport  (commutatif
 *   → requête et réponse hashent pareil) ; on tente le tuple direct puis
 *   le tuple inversé src↔dst pour rattacher la réponse à sa requête.
 * ================================================================ */
struct dns_flow {
    u_int32_t hashval;
    u_int8_t  ip_version;           /* 4 ou 6 */
    u_int8_t  l4proto;              /* IPPROTO_UDP / IPPROTO_TCP */
    u_int8_t  saddr[16], daddr[16]; /* ordre réseau (v4 = 4 premiers octets) */
    u_int16_t sport, dport;         /* ordre réseau */
    struct ndpi_flow_struct *ndpi_flow;
    time_t    last_seen;
};

static int flow_cmp(const void *a, const void *b)
{
    const struct dns_flow *fa = a, *fb = b;
    if (fa->hashval    != fb->hashval)    return fa->hashval    < fb->hashval    ? -1 : 1;
    if (fa->ip_version != fb->ip_version) return fa->ip_version < fb->ip_version ? -1 : 1;
    if (fa->l4proto    != fb->l4proto)    return fa->l4proto    < fb->l4proto    ? -1 : 1;
    int alen = (fa->ip_version == 6) ? 16 : 4;
    int r = memcmp(fa->saddr, fb->saddr, alen); if (r) return r;
    if (fa->sport != fb->sport) return fa->sport < fb->sport ? -1 : 1;
    r = memcmp(fa->daddr, fb->daddr, alen); if (r) return r;
    if (fa->dport != fb->dport) return fa->dport < fb->dport ? -1 : 1;
    return 0;
}

static u_int32_t flow_hashval(const struct dns_flow *f)
{
    int alen = (f->ip_version == 6) ? 16 : 4;
    u_int32_t h = f->l4proto + ntohs(f->sport) + ntohs(f->dport);
    for (int i = 0; i < alen; i++) h += f->saddr[i] + f->daddr[i];   /* symétrique src↔dst */
    return h;
}

/* Remplit `key` depuis un paquet IP brut (début = en-tête IP).
 * Retourne 1 si DNS (UDP/TCP, port 53), 0 sinon. *is_response = (sport==53).
 * *dns_off = offset du message DNS dans pkt (en-tête UDP sauté ; en TCP,
 * doff + préfixe de longueur 2 octets). */
static int parse_dns_tuple(const unsigned char *pkt, int len,
                           struct dns_flow *key, int *is_response,
                           int *dns_off)
{
    if (len < 1) return 0;
    int ver = pkt[0] >> 4;
    int l4off;
    u_int8_t proto;
    memset(key, 0, sizeof(*key));

    if (ver == 4) {
        if (len < 20) return 0;
        int ihl = (pkt[0] & 0x0f) * 4;
        if (ihl < 20 || len < ihl + 4) return 0;
        proto = pkt[9];
        memcpy(key->saddr, pkt + 12, 4);
        memcpy(key->daddr, pkt + 16, 4);
        l4off = ihl;
        key->ip_version = 4;
    } else if (ver == 6) {
        if (len < 44) return 0;
        proto = pkt[6];                 /* next header (pas de gestion d'extensions) */
        memcpy(key->saddr, pkt + 8,  16);
        memcpy(key->daddr, pkt + 24, 16);
        l4off = 40;
        key->ip_version = 6;
    } else {
        return 0;
    }

    if (proto != IPPROTO_UDP && proto != IPPROTO_TCP) return 0;
    key->l4proto = proto;
    memcpy(&key->sport, pkt + l4off,     2);
    memcpy(&key->dport, pkt + l4off + 2, 2);

    u_int16_t p53 = htons(53);
    if (key->sport != p53 && key->dport != p53) return 0;
    *is_response = (key->sport == p53);

    if (proto == IPPROTO_UDP) {
        *dns_off = l4off + 8;
    } else {                                    /* TCP : doff + préfixe 2 o */
        if (len < l4off + 13) return 0;
        int doff = (pkt[l4off + 12] >> 4) * 4;
        if (doff < 20) return 0;
        *dns_off = l4off + doff + 2;
    }

    key->hashval = flow_hashval(key);
    return 1;
}

/* Recherche bidirectionnelle ; crée l'entrée si absente.
 * Retourne NULL si table pleine (l'appelant bascule en flow transitoire). */
static struct dns_flow *flow_get_or_create(const struct dns_flow *key,
                                           time_t now, int *created)
{
    *created = 0;
    int idx = key->hashval % FLOW_HASH_ROOTS;

    void *r = ndpi_tfind(key, &flow_roots[idx], flow_cmp);
    if (!r) {
        /* tuple inversé : la réponse retrouve la requête (même hashval, même idx) */
        struct dns_flow rev = *key;
        memcpy(rev.saddr, key->daddr, 16);
        memcpy(rev.daddr, key->saddr, 16);
        rev.sport = key->dport;
        rev.dport = key->sport;
        r = ndpi_tfind(&rev, &flow_roots[idx], flow_cmp);
    }
    if (r) {
        struct dns_flow *f = *(struct dns_flow **)r;
        f->last_seen = now;
        return f;
    }

    if (g_flow_count >= MAX_DNS_FLOWS) return NULL;

    struct dns_flow *nf = calloc(1, sizeof(*nf));
    if (!nf) return NULL;
    *nf = *key;
    nf->ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (!nf->ndpi_flow) { free(nf); return NULL; }
    memset(nf->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
    nf->last_seen = now;

    if (ndpi_tsearch(nf, &flow_roots[idx], flow_cmp) == NULL) {
        ndpi_free_flow(nf->ndpi_flow);
        free(nf);
        return NULL;
    }
    g_flow_count++;
    *created = 1;
    return nf;
}

static void flow_delete(struct dns_flow *f)
{
    int idx = f->hashval % FLOW_HASH_ROOTS;
    ndpi_tdelete(f, &flow_roots[idx], flow_cmp);
    if (f->ndpi_flow) ndpi_free_flow(f->ndpi_flow);
    free(f);
    g_flow_count--;
}

/* Balayage d'expiration. twalk interdit la suppression en cours de
 * parcours → on collecte d'abord, on supprime ensuite. */
static struct dns_flow *expire_buf[EXPIRE_BATCH];
static int    expire_n;
static time_t expire_now;

static void expire_walker(const void *node, ndpi_VISIT which, int depth, void *ud)
{
    (void)depth; (void)ud;
    if (which != ndpi_preorder && which != ndpi_leaf) return;   /* chaque nœud une fois */
    struct dns_flow *f = *(struct dns_flow **)node;
    if (expire_now - f->last_seen >= FLOW_IDLE_SEC && expire_n < EXPIRE_BATCH)
        expire_buf[expire_n++] = f;
}

static void flow_table_sweep(time_t now)
{
    if (g_flow_count == 0)
        return;
    expire_now = now;
    expire_n = 0;
    for (int i = 0; i < FLOW_HASH_ROOTS; i++)
        if (flow_roots[i]) ndpi_twalk(flow_roots[i], expire_walker, NULL);
    for (int j = 0; j < expire_n; j++)
        flow_delete(expire_buf[j]);
}

/* Purge totale (arrêt) : on force l'expiration de tout, par lots. */
static void flow_table_free_all(void)
{
    while (g_flow_count > 0) {
        int before = g_flow_count;
        expire_now = time(NULL) + FLOW_IDLE_SEC;   /* rend tout "expiré" */
        expire_n = 0;
        for (int i = 0; i < FLOW_HASH_ROOTS; i++)
            if (flow_roots[i]) ndpi_twalk(flow_roots[i], expire_walker, NULL);
        for (int j = 0; j < expire_n; j++)
            flow_delete(expire_buf[j]);
        if (g_flow_count == before) break;          /* garde-fou anti-boucle */
    }
}

/* ================================================================
 * Callback NFQUEUE
 * ================================================================ */
static int sdwan_nfq_cb(const struct nlmsghdr *nlh, void *data)
{
    struct mnl_socket *nl = (struct mnl_socket *)data;
    struct nlattr *attr[NFQA_MAX + 1] = {};
    uint32_t pkt_id = 0;

    /* Même si le parse échoue, les attributs déjà extraits (dont le
     * PACKET_HDR) restent exploitables : on n'abandonne PAS sans verdict,
     * sinon le slot NFQUEUE du paquet fuit jusqu'au déclenchement du bypass
     * (DNS sauf, mais classification silencieusement morte). */
    int parse_ok = (nfq_nlmsg_parse(nlh, attr) >= 0);

    if (attr[NFQA_PACKET_HDR]) {
        struct nfqnl_msg_packet_hdr *ph =
            mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);
        pkt_id = ntohl(ph->packet_id);
    } else {
        /* Sans packet_id, aucun verdict possible : message NFQUEUE malformé
         * (jamais vu en pratique) ; ce slot-là sera couvert par le bypass. */
        return MNL_CB_ERROR;
    }

    if (parse_ok && attr[NFQA_PAYLOAD]) {
        int pktlen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
        unsigned char *pkt = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);

        struct dns_flow key;
        int is_response = 0;
        int dns_off = 0;

        if (parse_dns_tuple(pkt, pktlen, &key, &is_response, &dns_off)) {
            struct timeval tv;
            gettimeofday(&tv, NULL);    /* horloge unique : now + ts nDPI */
            time_t now = tv.tv_sec;
            int created = 0;

            /* Flow persistant (corrélation requête↔réponse). Si la table est
             * pleine, on bascule sur un flow transitoire (dégradation : la
             * réponse ne pourra pas être corrélée, mais le DNS n'est jamais
             * bloqué). */
            struct dns_flow *f = flow_get_or_create(&key, now, &created);
            struct ndpi_flow_struct *transient = NULL;
            struct ndpi_flow_struct *nf;

            if (f) {
                nf = f->ndpi_flow;
            } else {
                transient = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
                if (transient) memset(transient, 0, SIZEOF_FLOW_STRUCT);
                nf = transient;
            }

            if (nf) {
                uint64_t ts = (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;

                ndpi_protocol proto = ndpi_detection_process_packet(
                    ndpi_mod, nf, pkt, pktlen, ts, NULL);
                u_int16_t app_id = proto.proto.app_protocol;

                if (is_response) {
                    /* Fallback : réponse sans requête vue (ou classif non
                     * encore décidée) → forcer la meilleure estimation nDPI
                     * (s'appuie sur le qname de la section question). */
                    if (app_id == NDPI_PROTOCOL_UNKNOWN) {
                        proto = ndpi_detection_giveup(ndpi_mod, nf);
                        app_id = proto.proto.app_protocol;
                    }

                    /* Injection AVANT le verdict (ordre critique : le set doit
                     * être peuplé avant que le client n'émette son SYN). */
                    if (app_id != NDPI_PROTOCOL_UNKNOWN &&
                        app_id != NDPI_PROTOCOL_DNS &&
                        app_id < PROTO_TABLE_SIZE &&
                        proto_has_set[app_id]) {
                        if (nf->protos.dns.num_rsp_addr > 0)
                            inject_ips(app_id, nf);
                        /* Réponse à une question HTTPS RR (type 65) : nDPI
                         * n'extrait pas les ipv4hint des RDATA SVCB → on
                         * parcourt les answers nous-mêmes. */
                        if (nf->protos.dns.query_type == 65 &&
                            dns_off > 0 && dns_off < pktlen)
                            svcb_inject_hints(app_id, nf->host_server_name,
                                              pkt + dns_off, pktlen - dns_off);
                    }

                    /* Transaction terminée → purge l'entrée. APRÈS ce point,
                     * nf/f/transient sont libérés : INTERDICTION absolue de les
                     * déréférencer en dessous. Le verdict NF_ACCEPT n'utilise
                     * que pkt_id (copié plus haut) et nl. On annule les
                     * pointeurs pour qu'un futur usage accidentel crashe en
                     * NULL-deref évident plutôt qu'en UAF silencieux. */
                    if (f) flow_delete(f);
                    else   ndpi_free_flow(transient);
                    f = NULL; transient = NULL; nf = NULL;
                } else {
                    /* Requête : on conserve le flow persistant pour corréler la
                     * réponse à venir. En transitoire (table pleine), rien à
                     * garder. */
                    if (transient) { ndpi_free_flow(transient); transient = NULL; nf = NULL; }
                }
            }
        }
    }

    /* Verdict NF_ACCEPT */
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *v = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, QUEUE_NUM);
    nfq_nlmsg_verdict_put(v, pkt_id, NF_ACCEPT);

    if (mnl_socket_sendto(nl, v, v->nlmsg_len) < 0)
        syslog(LOG_ERR, "verdict: %s", strerror(errno));

    return MNL_CB_OK;
}

/* ================================================================
 * Setup NFQUEUE
 * ================================================================ */
/* Envoie un message de config NFQUEUE avec NLM_F_ACK et ATTEND la réponse
 * kernel. Sans ACK, un échec (module nfnetlink_queue inchargeable, ex.
 * kernel booté ≠ RPM kernel installé) passe inaperçu : le daemon tournerait
 * avec une interception morte. 0 = OK, -1 = NACK/erreur (errno posé). */
static int nfq_cfg_xchg(struct mnl_socket *nl, struct nlmsghdr *nlh)
{
    char ack[MNL_SOCKET_BUFFER_SIZE];
    nlh->nlmsg_flags |= NLM_F_ACK;
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
        return -1;
    int n = mnl_socket_recvfrom(nl, ack, sizeof ack);
    if (n < 0)
        return -1;
    return (mnl_cb_run(ack, n, 0, mnl_socket_get_portid(nl), NULL, NULL) == -1) ? -1 : 0;
}

static struct mnl_socket *setup_nfqueue(uint16_t queue_num)
{
    struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
    if (!nl) {
        syslog(LOG_CRIT, "mnl_socket_open: %s", strerror(errno));
        return NULL;
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        syslog(LOG_CRIT, "mnl_socket_bind: %s", strerror(errno));
        mnl_socket_close(nl);
        return NULL;
    }

    /* Garde-fou sur les échanges de config ci-dessous (ACK attendus). Reste
     * actif ensuite sans effet : la boucle principale est protégée par
     * select() et ne recv() que lorsqu'il y a des données. */
    struct timeval cfg_tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_RCVTIMEO, &cfg_tv, sizeof cfg_tv);

    char buf[MNL_SOCKET_BUFFER_SIZE];

    /* BIND */
    struct nlmsghdr *nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);
    if (nfq_cfg_xchg(nl, nlh) < 0) {
        syslog(LOG_CRIT, "nfqueue bind %u: %s — NFQUEUE indisponible "
               "(module nfnetlink_queue inchargeable ?)",
               queue_num, strerror(errno));
        mnl_socket_close(nl);
        return NULL;
    }

    /* COPY_PACKET — payload complet pour nDPI ; qmaxlen élevé pour absorber
     * les rafales DNS. FAIL_OPEN indispensable : queue PLEINE → le kernel
     * ACCEPT (paquet non classé, routage par défaut) au lieu de DROP. Le
     * `bypass` des règles ne couvre, lui, QUE l'absence de listener
     * (-ESRCH) — sans ce flag, une rafale au-delà de qmaxlen casserait du
     * DNS client au lieu de dégrader la classification. */
    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xFFFF);
    nfq_nlmsg_cfg_put_qmaxlen(nlh, 8192);
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_FAIL_OPEN));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK,  htonl(NFQA_CFG_F_FAIL_OPEN));
    if (nfq_cfg_xchg(nl, nlh) < 0) {
        syslog(LOG_CRIT, "nfqueue config %u: %s", queue_num, strerror(errno));
        mnl_socket_close(nl);
        return NULL;
    }

    return nl;
}

/* ================================================================
 * Règles d'interception DNS (auto-gérées par le daemon)
 *
 * Table dédiée `inet dnsteerd_filter`, séparée du pare-feu hôte (survit à
 * ses régénérations tant qu'il flush SES chaînes et non le ruleset entier).
 * priority -175 = après
 * conntrack/defrag (-200), AVANT iptables mangle (-150) et filter (0) → on
 * voit le DNS avant tout marquage/drop. `bypass` = fail-open.
 * ================================================================ */
static int run_nft_script(const char *script)
{
    struct nft_ctx *c = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!c) return -1;
    int rc = nft_run_cmd_from_buffer(c, script);
    nft_ctx_free(c);
    return rc;
}

static void setup_intercept(void)
{
    char s[1024];
    /* add+flush = idempotent (repart propre même si la table existait). */
    snprintf(s, sizeof s,
        "add table inet dnsteerd_filter\n"
        "flush table inet dnsteerd_filter\n"
        "add chain inet dnsteerd_filter dns_intercept "
            "{ type filter hook prerouting priority -175 ; policy accept ; }\n"
        "add chain inet dnsteerd_filter dns_local "
            "{ type filter hook output priority -175 ; policy accept ; }\n"
        "add rule inet dnsteerd_filter dns_intercept udp sport 53 queue num %d bypass\n"
        "add rule inet dnsteerd_filter dns_intercept udp dport 53 queue num %d bypass\n"
        "add rule inet dnsteerd_filter dns_local udp dport 53 queue num %d bypass\n",
        QUEUE_NUM, QUEUE_NUM, QUEUE_NUM);
    if (run_nft_script(s) != 0)
        syslog(LOG_WARNING, "setup_intercept: échec ruleset nft");
    else
        syslog(LOG_INFO, "intercept: table inet dnsteerd_filter active (queue %d)",
               QUEUE_NUM);
}

static void teardown_intercept(void)
{
    run_nft_script("delete table inet dnsteerd_filter\n");
}

/* ================================================================
 * Mode BOOT
 * ================================================================ */
static int do_boot(void)
{
    openlog("dnsteerd",LOG_PID, LOG_DAEMON);

    struct ndpi_detection_module_struct *ctx = init_ndpi();
    if (!ctx)
        return 1;

    nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft) {
        ndpi_exit_detection_module(ctx);
        return 1;
    }

    ndpi_proto_defaults_t *defaults = ndpi_get_proto_defaults(ctx);
    u_int num = ndpi_get_num_protocols(ctx);
    int count = 0;

    /* Création des sets batchée : on accumule les commandes "add set" dans un
     * gros buffer et on ne parse/transige qu'une fois par lot (~1 parse pour
     * ~500 sets) au lieu d'un parse flex/bison par set → boot rapide. */
    char setbuf[32768];
    int  setoff = 0;
    /* add table idempotent en tête du premier lot : indispensable au profil
     * neutre (table dédiée), no-op si la table existe déjà (intégration
     * sur table partagée). */
    setoff = snprintf(setbuf, sizeof(setbuf), "add table " NFT_TABLE "\n");

    /* Genere aussi un JSON pour le daemon (handler sdwan.protocols).
     * Ecriture atomique : tmp + rename. */
    char tmppath[256];
    snprintf(tmppath, sizeof(tmppath), "%s.tmp", PROTOS_JSON_PATH);
    mkdir(RUNTIME_DIR, 0755);           /* profil neutre : /run/<nom> à créer */
    FILE *jf = fopen(tmppath, "w");
    int json_first = 1;
    if (jf)
        fputs("[", jf);
    else
        syslog(LOG_WARNING, "boot: %s: %s (l'UI n'aura pas la liste des protocoles)",
               tmppath, strerror(errno));

    for (u_int i = 0; i < num; i++) {
        if (!defaults[i].isAppProtocol)
            continue;
        if (defaults[i].protoId == NDPI_PROTOCOL_UNKNOWN)
            continue;

        u_int16_t id = defaults[i].protoId;

        int w = snprintf(setbuf + setoff, sizeof(setbuf) - setoff,
                         "add set " NFT_TABLE " " SET_V4 "%u"
                         " { type ipv4_addr ; flags timeout ; }\n", id);
        if (w > 0) setoff += w;
        if (DNSTEERD_IPV6) {
            w = snprintf(setbuf + setoff, sizeof(setbuf) - setoff,
                         "add set " NFT_TABLE " " SET_V6 "%u"
                         " { type ipv6_addr ; flags timeout ; }\n", id);
            if (w > 0) setoff += w;
        }
        count++;
        /* marge 256 : jusqu'à 2 lignes (~150 o) ajoutées par protocole */
        if (setoff > (int)sizeof(setbuf) - 256) {   /* flush le lot avant débordement */
            if (nft_run_cmd_from_buffer(nft, setbuf) != 0)
                syslog(LOG_ERR, "boot: échec d'un lot 'add set' (injections ENOENT à prévoir)");
            setoff = 0; setbuf[0] = 0;
        }

        if (jf) {
            const char *cat = ndpi_category_get_name(ctx,
                defaults[i].protoCategory);
            const char *breed = ndpi_get_proto_breed_name(
                defaults[i].protoBreed);
            fprintf(jf, "%s{\"id\":%u,\"name\":\"%s\","
                "\"category\":\"%s\",\"breed\":\"%s\"}",
                json_first ? "" : ",",
                id,
                defaults[i].protoName,
                cat ? cat : "",
                breed ? breed : "");
            json_first = 0;
        }
    }

    /* Flush du dernier lot de sets. */
    if (setoff > 0 && nft_run_cmd_from_buffer(nft, setbuf) != 0)
        syslog(LOG_ERR, "boot: échec du dernier lot 'add set' (injections ENOENT à prévoir)");

    if (jf) {
        fputs("]\n", jf);
        fclose(jf);
        if (rename(tmppath, PROTOS_JSON_PATH) != 0)
            syslog(LOG_WARNING, "boot: rename %s -> %s : %m",
                   tmppath, PROTOS_JSON_PATH);
    }

    if (DNSTEERD_IPV6)
        syslog(LOG_INFO, "boot: %d app protocols → %d sets v4 + %d sets v6",
               count, count, count);
    else
        syslog(LOG_INFO, "boot: %d app protocols → %d sets v4", count, count);

    nft_ctx_free(nft);
    nft = NULL;
    ndpi_exit_detection_module(ctx);
    closelog();
    return 0;
}

/* ================================================================
 * Mode DAEMON
 * ================================================================ */
static int do_daemon(int foreground)
{
    if (!foreground) {
        if (daemon(0, 0) < 0) {
            perror("daemon");
            return 1;
        }
    }

    openlog("dnsteerd",LOG_PID | LOG_NDELAY, LOG_DAEMON);
    write_pidfile();

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    /* nDPI */
    ndpi_mod = init_ndpi();
    if (!ndpi_mod)
        return 1;

    /* Enumérer les protos et remplir proto_has_set[] */
    ndpi_proto_defaults_t *defaults = ndpi_get_proto_defaults(ndpi_mod);
    u_int num = ndpi_get_num_protocols(ndpi_mod);
    int count = 0;

    memset(proto_has_set, 0, sizeof(proto_has_set));
    for (u_int i = 0; i < num; i++) {
        if (!defaults[i].isAppProtocol)
            continue;
        if (defaults[i].protoId == NDPI_PROTOCOL_UNKNOWN)
            continue;
        u_int16_t id = defaults[i].protoId;
        if (id < PROTO_TABLE_SIZE) {
            proto_has_set[id] = 1;
            count++;
        }
    }
    syslog(LOG_INFO, "daemon: %d app protocols loaded", count);

    /* Socket netlink persistant pour l'injection (libnftnl) — pas de
     * libnftables sur le chemin chaud. */
    if (nft_open() < 0) {
        syslog(LOG_CRIT, "nft_open failed");
        return 1;
    }

    /* NFQUEUE */
    struct mnl_socket *nl = setup_nfqueue(QUEUE_NUM);
    if (!nl)
        return 1;

    syslog(LOG_INFO, "daemon: listening on NFQUEUE %d", QUEUE_NUM);

    /* Monter l'interception une fois le listener prêt (évite que des paquets
     * soient queués sans personne — bypass les laisserait passer non classés). */
    setup_intercept();

    int fd = mnl_socket_get_fd(nl);
    uint32_t portid = mnl_socket_get_portid(nl);
    /* 64 Ko + marge : copy_range = 0xFFFF et le defrag (-400) réassemble
     * AVANT nous (-175) → une réponse DNS fragmentée réassemblée peut
     * dépasser 8 Ko ; dans un buffer trop court elle arriverait tronquée et
     * serait verdictée sans être classée. */
    static char recv_buf[0xFFFF + 4096];

    while (keep_running) {
        /* Expiration des flows DNS orphelins (requête sans réponse, etc.) */
        time_t now_sweep = time(NULL);
        if (now_sweep - g_last_sweep >= FLOW_SWEEP_SEC) {
            flow_table_sweep(now_sweep);
            g_last_sweep = now_sweep;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int ret = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            syslog(LOG_ERR, "select: %s", strerror(errno));
            break;
        }
        if (ret == 0)
            continue;

        int n = mnl_socket_recvfrom(nl, recv_buf, sizeof(recv_buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            syslog(LOG_ERR, "recvfrom: %s", strerror(errno));
            break;
        }

        mnl_cb_run(recv_buf, n, 0, portid, sdwan_nfq_cb, nl);
    }

    /* Cleanup */
    syslog(LOG_INFO, "daemon: shutting down");
    teardown_intercept();
    mnl_socket_close(nl);
    flow_table_free_all();
    nft_close();
    ndpi_exit_detection_module(ndpi_mod);
    unlink(PIDFILE);
    closelog();
    return 0;
}

/* ================================================================
 * Mode LIST
 * ================================================================ */
static int do_list(void)
{
    struct ndpi_detection_module_struct *ctx = init_ndpi();
    if (!ctx)
        return 1;

    ndpi_proto_defaults_t *defaults = ndpi_get_proto_defaults(ctx);
    u_int num = ndpi_get_num_protocols(ctx);

    printf("%-6s %-32s %-20s %s\n",
           "ID", "Name", "Category", "Breed");
    printf("------+--------------------------------+"
           "--------------------+--------\n");

    int count = 0;
    for (u_int i = 0; i < num; i++) {
        if (!defaults[i].isAppProtocol)
            continue;
        if (defaults[i].protoId == NDPI_PROTOCOL_UNKNOWN)
            continue;

        printf("%-6u %-32s %-20s %s\n",
               defaults[i].protoId,
               defaults[i].protoName,
               ndpi_category_get_name(ctx, defaults[i].protoCategory),
               ndpi_get_proto_breed_name(defaults[i].protoBreed));
        count++;
    }

    printf("\nTotal: %d app protocols\n", count);
    ndpi_exit_detection_module(ctx);
    return 0;
}

/* ================================================================
 * Mode SETS — element counts per protocol (JSON stdout)
 * Output: [{id, v4, v6}, ...] (only non-empty sets)
 * ================================================================ */
static int do_sets(void)
{
    if (nft_open() < 0) {
        fprintf(stderr, "netlink open failed\n");
        return 1;
    }

    int ids[PROTO_TABLE_SIZE];
    int nids = 0;
    collect_set_ids(ids, &nids, PROTO_TABLE_SIZE);

    printf("[");
    int first = 1;

    for (int i = 0; i < nids; i++) {
        struct elem_dump c = { .out = NULL, .first = 1, .count = 0 };
        dump_set_elems(SET_V4, ids[i], &c);
        struct elem_dump c6 = { .out = NULL, .first = 1, .count = 0 };
        if (DNSTEERD_IPV6)
            dump_set_elems(SET_V6, ids[i], &c6);

        if (c.count + c6.count > 0) {
            printf("%s{\"id\":%d,\"v4\":%d,\"v6\":%d}",
                   first ? "" : ",", ids[i], c.count, c6.count);
            first = 0;
        }
    }

    printf("]\n");
    nft_close();
    return 0;
}

/* ================================================================
 * Mode SET-ELEMENTS — IPs d'un set specifique
 * Défaut : JSON {v4: [{ip,timeout,expires},...], v6: [...]} (UI)
 * Option -t : liste lisible « protocol <Nom> (<id>): » + une IP par ligne
 * ================================================================ */
/* Nom d'une app depuis le JSON écrit par `boot` (notre propre format,
 * champs id puis name dans un ordre fixe) ; fallback = l'id en texte.
 * Évite de recharger tout le moteur nDPI pour un simple affichage. */
static void proto_name_from_json(int id, char *out, size_t sz)
{
    snprintf(out, sz, "%d", id);                 /* fallback */
    FILE *f = fopen(PROTOS_JSON_PATH, "r");
    if (!f)
        return;
    static char jbuf[131072];
    size_t n = fread(jbuf, 1, sizeof jbuf - 1, f);
    fclose(f);
    jbuf[n] = 0;

    char pat[32];
    snprintf(pat, sizeof pat, "{\"id\":%d,\"name\":\"", id);
    char *p = strstr(jbuf, pat);
    if (!p)
        return;
    p += strlen(pat);
    char *e = strchr(p, '"');
    if (!e || (size_t)(e - p) >= sz)
        return;
    memcpy(out, p, (size_t)(e - p));
    out[e - p] = 0;
}

static int do_set_elements(const char *id_str, int text_mode)
{
    int id = atoi(id_str);
    if (id <= 0) {
        fprintf(stderr, "Invalid protocol ID: %s\n", id_str);
        return 1;
    }

    if (nft_open() < 0)
        return 1;

    if (text_mode) {
        char pname[64];
        proto_name_from_json(id, pname, sizeof pname);
        printf("protocol %s (%d):\n", pname, id);
        struct elem_dump c = { .out = stdout, .text = 1, .first = 1, .count = 0 };
        dump_set_elems(SET_V4, id, &c);
        if (DNSTEERD_IPV6)
            dump_set_elems(SET_V6, id, &c);
        printf("%d element(s)\n", c.count);
    } else {
        printf("{\"v4\":[");
        struct elem_dump c = { .out = stdout, .first = 1, .count = 0 };
        dump_set_elems(SET_V4, id, &c);
        printf("],\"v6\":[");
        if (DNSTEERD_IPV6) {
            c.first = 1;
            dump_set_elems(SET_V6, id, &c);
        }
        printf("]}\n");
    }

    nft_close();
    return 0;
}

/* ================================================================
 * Usage / Main
 * ================================================================ */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s <mode> [options]\n"
        "\n"
        "Modes:\n"
        "  boot              Create nftables sets for nDPI app protocols\n"
        "  daemon            Run DNS NFQUEUE daemon\n"
        "  list              List nDPI app protocols and exit\n"
        "  sets              Output element counts per set (JSON)\n"
        "  set-elements <id> Output IPs in a specific set (JSON)\n"
        "\n"
        "Options:\n"
        "  -f       Foreground (daemon mode only)\n"
        "  -t       Plain-text output (set-elements mode only)\n"
        "  -h       This help\n",
        prog);
}

int main(int argc, char *argv[])
{
    int foreground = 0;
    int text_mode = 0;
    int opt;

    while ((opt = getopt(argc, argv, "fth")) != -1) {
        switch (opt) {
        case 'f': foreground = 1; break;
        case 't': text_mode = 1; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return 1;
    }

    const char *mode = argv[optind];

    if (strcmp(mode, "boot") == 0)
        return do_boot();
    else if (strcmp(mode, "daemon") == 0)
        return do_daemon(foreground);
    else if (strcmp(mode, "list") == 0)
        return do_list();
    else if (strcmp(mode, "sets") == 0)
        return do_sets();
    else if (strcmp(mode, "set-elements") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Usage: %s set-elements [-t] <protocol-id>\n", argv[0]);
            return 1;
        }
        return do_set_elements(argv[optind + 1], text_mode);
    } else {
        fprintf(stderr, "Unknown mode: %s\n", mode);
        usage(argv[0]);
        return 1;
    }
}
