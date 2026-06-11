# dnsteerd

**Daemon de routage applicatif piloté par le DNS (« first-packet traffic
steering »).**

*English version: [README.md](README.md)*

dnsteerd permet de router le trafic **par application** (Windows Update,
Netflix, Microsoft 365, …) dès le **premier paquet** de chaque connexion,
avec les outils standards du noyau Linux (nftables + policy routing).

## Le problème

Les classifieurs DPI par flux (xt_ndpi, etc.) identifient l'application en
observant les premiers paquets **d'une connexion déjà ouverte** : le ou les
premiers paquets partent donc toujours par la mauvaise route, et une
connexion déjà routée ne peut plus changer de chemin.

## Le principe

dnsteerd renverse l'approche : l'application est connue **avant** la
connexion, au moment de la résolution DNS.

1. Les paquets DNS (UDP/53) sont interceptés via NFQUEUE (queue 200) par
   une table nftables dédiée `inet dnsteerd_filter`, créée et supprimée
   par le daemon lui-même (hooks prerouting + output, priority -175,
   `bypass` = fail-open).
2. Chaque réponse DNS est classifiée par **nDPI** à partir du nom demandé
   (`host_server_name`) → identifiant d'application (`app_protocol`).
3. Les adresses A de la réponse sont injectées dans le set nftables
   `ndpi_v4_<app_id>` avec un timeout égal au TTL de l'enregistrement
   (borné 60 s – 24 h), **avant** de rendre le verdict NF_ACCEPT —
   garantie d'ordre : quand le client reçoit la réponse et émet son SYN,
   le set est déjà peuplé.
4. Le routage est ensuite l'affaire de l'hôte : une règle de policy
   routing qui matche le set (`ip daddr @ndpi_v4_<id>`) marque la
   connexion vers la table de routage voulue.

La corrélation requête↔réponse est conservée par une table de flows
(clé symétrique façon ndpiReader) pour attribuer la réponse au nom
demandé même à travers les CNAME de CDN.

Tout est **fail-open** : règles `queue ... bypass` (daemon absent →
le DNS passe), flag `NFQA_CFG_F_FAIL_OPEN` (queue saturée → les paquets
passent non classés), `qmaxlen 8192`. Le DNS n'est jamais bloqué ; au
pire la classification se dégrade et le trafic suit la route par défaut.

## Préparer sa machine

### Noyau

- nftables (`nf_tables`) et NFQUEUE : modules `nfnetlink_queue` et
  `nft_queue` disponibles pour le **kernel en cours d'exécution**.

```sh
modprobe nfnetlink_queue        # nft_queue se charge tout seul à la pose de la règle
```

> ⚠️ Piège vécu : après une mise à jour du paquet kernel **sans reboot**,
> les modules du kernel encore en mémoire ne sont plus chargeables
> (`/lib/modules/$(uname -r)` a disparu) — toute règle `queue` est alors
> rejetée `ENOENT`, et le batch nft étant atomique, l'erreur semble porter
> sur le `add table`. Vérifiez `uname -r` vs le kernel installé, rebootez
> si besoin.

### Bibliothèques

Build : gcc, make, et les en-têtes de :

- `libmnl`
- `libnetfilter_queue`
- `libnftables` (nftables ≥ 0.9)
- `libnftnl`
- **nDPI ≥ 5.0** (avec `dns.subclassification`)

Exécution : les bibliothèques partagées correspondantes, et **root**
(sockets netlink + nftables).

### Build

```sh
make            # binaire ./dnsteerd
make install    # PREFIX=/usr/local par défaut
```

Intégration plateforme : créez un fichier local `profile.h` (git-ignoré)
pour surcharger les valeurs de `defaults.h` (table nftables, chemins
runtime, fichier de protocoles custom). Sans `profile.h`, dnsteerd
utilise une table dédiée `inet dnsteerd` et `/run/dnsteerd/`.

## Démarrage

```sh
dnsteerd boot           # crée la table/les sets ndpi_v4_<id> + le JSON des protocoles
dnsteerd daemon         # lance le daemon (option -f : avant-plan)
```

Inspection :

```sh
dnsteerd list                # protocoles applicatifs nDPI connus
dnsteerd sets                # compte d'IPs par set non vide (JSON)
dnsteerd set-elements <id>   # IPs d'un set, avec timeout/expires (JSON)
```

## Exploiter les sets pour router

Exemple minimal : envoyer Netflix (id 133) par un second lien.

```sh
# marquer les nouvelles connexions vers les IPs résolues de l'app
nft add rule inet mytable mangle_out 'ip daddr @ndpi_v4_133 meta mark set 0x2 counter'

# router le mark vers la table 100
ip rule add fwmark 0x2 table 100
ip route add default via 192.0.2.254 table 100
```

(En pratique on combine avec `ct mark` save/restore pour que toute la
connexion garde sa route.)

## Protocoles custom

Déclarez vos propres applications dans `CUSTOM_PROTOS_PATH`
(`/etc/dnsteerd/custom_protocols.txt` par défaut), au format nDPI :

```
host:"mycdn.example.com"@MonApp
host:".update.vendor.example"@VendorUpdate
```

Ils reçoivent un id, un set et apparaissent dans `dnsteerd list` comme
les protocoles natifs.

## Limitations connues (assumées)

- **IPv4 seulement** pour l'instant — unification v4/v6 prévue.
- **DNS UDP seulement** : le repli DNS/TCP (réponses tronquées) n'est pas
  intercepté ; rare en pratique avec EDNS0.
- **DoH/DoT invisibles** : un client qui résout en DNS chiffré ne passe
  pas par l'interception — son trafic suit la route par défaut
  (dégradation, pas de coupure).
- Le re-add d'une IP déjà présente **ne rafraîchit pas** son timeout
  (comportement nf_tables) ; sans incidence dans les topologies à
  résolveur cache, dont les TTL décomptent en cascade.

## Crédits

dnsteerd s'appuie sur **[nDPI](https://github.com/ntop/nDPI)**, la
bibliothèque d'inspection profonde de paquets du projet
[ntop](https://www.ntop.org/) (LGPL-3), pour la classification applicative
des noms DNS — dont le mécanisme de protocoles custom
(`ndpi_load_protocols_file`) réutilisé tel quel.

Côté noyau, il utilise les bibliothèques du projet
[netfilter](https://netfilter.org/) :
[libmnl](https://netfilter.org/projects/libmnl/),
[libnetfilter_queue](https://netfilter.org/projects/libnetfilter_queue/),
[libnftnl](https://netfilter.org/projects/libnftnl/) et libnftables
(nftables).

## Licence

GPL-2.0-or-later — Copyright (C) 2026 Didier Gaudin
&lt;didier.gaudin@gmail.com&gt;
