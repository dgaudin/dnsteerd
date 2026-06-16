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
3. Les adresses A/AAAA de la réponse — et les **`ipv4hint`/`ipv6hint`
   des enregistrements HTTPS** (type 65, RFC 9460, parsés par dnsteerd
   lui-même car nDPI ne décode pas les RDATA SVCB) — sont injectées dans
   les sets nftables `ndpi_v4_<app_id>` / `ndpi_v6_<app_id>` avec un
   timeout égal au TTL de l'enregistrement (borné 60 s – 24 h), **avant**
   de rendre le verdict NF_ACCEPT — garantie d'ordre : quand le client
   reçoit la réponse et émet son SYN, les sets sont déjà peuplés.
   (Les éléments v4 et v6 partent dans un seul batch netlink
   transactionnel.)
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

> Seuls les protocoles que nDPI classe **depuis un nom DNS** (patterns
> host/domaine) reçoivent un set. Les protocoles binaires/flux — média/VoIP
> comme `TeamsCall` (RTP/STUN), BitTorrent… — ne sont jamais joignables
> depuis le DNS et sont exclus (leur set resterait à jamais vide, et ils
> induiraient en erreur dans une UI de routage). La liste des routables est
> générée depuis la source nDPI par `gen_dns_protocols.sh` ; à régénérer lors
> d'un changement de version nDPI. Les protocoles custom (plus bas) sont
> host par définition, donc toujours routables.

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
- `libnftnl`
- `libnftables` (nftables ≥ 0.9) — hors chemin chaud, pour créer les sets
  et le ruleset d'interception
- **nDPI ≥ 5.0** (avec `dns.subclassification`)

Paquets par distribution :

```sh
# Debian / Ubuntu
apt install build-essential libmnl-dev libnetfilter-queue-dev \
            libnftnl-dev libnftables-dev libndpi-dev

# Fedora
dnf install gcc make libmnl-devel libnetfilter_queue-devel \
            libnftnl-devel nftables-devel ndpi-devel

# RHEL / Rocky / Alma — le header nftables-devel est dans le dépôt CRB,
# désactivé par défaut :
dnf config-manager --set-enabled crb
dnf install gcc make libmnl-devel libnetfilter_queue-devel \
            libnftnl-devel nftables-devel
# nDPI : via EPEL (ndpi-devel) ou compilé depuis https://github.com/ntop/nDPI
```

> Le header libnftables est `nftables/libnftables.h` (paquet
> `nftables-devel` sur RHEL-likes, `libnftables-dev` sur Debian). Si le
> compilateur ne le trouve pas, localisez le bon paquet avec
> `dnf provides '*/libnftables.h'` / `apt-file search libnftables.h`.

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

### Liste des protocoles routables

`dns_protocols.inc` (le tableau `dnsteerd_host_protos[]` compilé dans le
daemon) liste les protocoles classables via DNS/host (voir la note sous
[Le principe](#le-principe)). Il est **généré au build** par
`gen_dns_protocols.sh` depuis les tables host de nDPI et **n'est pas
committé** : il reflète votre nDPI exacte — éventuellement customisée — donc
on le régénère pour rester calé sur la lib liée.

⚠️ **Le `make install` de nDPI NE copie PAS ces fichiers `.inc`** (ils sont
internes à la compilation de nDPI). Le Makefile régénère `dns_protocols.inc`
quand il les trouve sous `$(NDPI_INC)` (défaut `/usr/include/ndpi`) ; absents,
il **échoue bruyamment** au lieu d'émettre une liste vide. Fournissez-les soit
en copiant les tables à côté des headers installés :

```sh
cp /chemin/nDPI/src/lib/ndpi_content_match.c.inc  /usr/include/ndpi/
cp -r /chemin/nDPI/src/lib/inc_generated          /usr/include/ndpi/
```

soit en pointant le générateur directement sur l'arbre source nDPI :

```sh
sh gen_dns_protocols.sh /chemin/nDPI/src/lib > dns_protocols.inc
```

Pour un build portable sans les tables nDPI, générez `dns_protocols.inc` une
fois et livrez-le avec votre paquet (à rafraîchir lors d'un bump nDPI).

## Démarrage

```sh
dnsteerd boot           # crée la table + les sets ndpi_v4_<id> / ndpi_v6_<id> + le JSON des protocoles
dnsteerd daemon         # lance le daemon (option -f : avant-plan)
```

Inspection :

```sh
dnsteerd list                # protocoles applicatifs nDPI connus
dnsteerd sets                # compte d'IPs par set non vide (JSON)
dnsteerd set-elements <id>   # IPs d'un set, avec timeout/expires (JSON)
dnsteerd set-elements -t <id> # idem, lisible (nom du protocole, une IP par ligne)
```

### Lancer en service

Le daemon doit tourner en **avant-plan** (`-f`) sous un superviseur de
process pour être relancé en cas d'arrêt — et `dnsteerd boot` doit tourner
**une fois avant lui** (le daemon injecte dans les sets que `boot` crée).

```ini
# /etc/systemd/system/dnsteerd.service
[Unit]
After=nftables.service network-online.target

[Service]
ExecStartPre=/usr/local/bin/dnsteerd boot
ExecStart=/usr/local/bin/dnsteerd daemon -f
Restart=always

[Install]
WantedBy=multi-user.target
```

Sur un système SysV/inittab, une ligne `respawn` marche aussi — avec
`dnsteerd boot` lancé plus tôt dans la séquence de boot :

```
dnst:23:respawn:/usr/local/bin/dnsteerd daemon -f
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

Pour l'IPv6, matchez le set `@ndpi_v6_<id>` correspondant et ajoutez une
`ip -6 rule` / `ip -6 route`. En pratique on combine aussi avec
`ct mark` save/restore pour que toute la connexion garde sa route.

## Protocoles custom

Déclarez vos propres applications dans `CUSTOM_PROTOS_PATH`
(`/etc/dnsteerd/custom_protocols.txt` par défaut), au format nDPI :

```
host:"mycdn.example.com"@MonApp
host:".update.vendor.example"@VendorUpdate
```

Ils reçoivent un id, un set et apparaissent dans `dnsteerd list` comme
les protocoles natifs.

### Microsoft 365 (local breakout)

Cas d'usage fréquent : le **local breakout** — sortir le trafic Microsoft 365
par un lien internet local/peu cher plutôt que de le backhauler sur un WAN
managé coûteux. nDPI fournit un snapshot *statique* curé des domaines M365 :
suffisant pour démarrer, mais il dérive de la liste live Microsoft, et tout
domaine non couvert reste silencieusement sur le mauvais lien.

`m365-sync.sh` maintient la couverture à jour depuis l'**API officielle
Microsoft** (`endpoints.office.com`). Il écrit les domaines en protocoles
custom dans le répertoire conf.d (`CUSTOM_PROTOS_DIR`), regroupés par service
dans les protocoles nDPI existants (Exchange→`Outlook`, SharePoint/Common→
`Microsoft365`, Skype→`Teams`) ; éditez la fonction `map_proto` pour regrouper
autrement. Il est idempotent (vérifie d'abord `/version` de l'API) et n'émet
que les catégories `Optimize`+`Allow` recommandées par Microsoft pour le
breakout (`M365_CATEGORIES` pour changer).

> Cela **sépare nativement le M365 métier des mises à jour en masse** :
> Microsoft classe son CDN / ses MàJ Office (`officecdn.microsoft.com`,
> `cdn.odc.officeapps.live.com`, …) en catégorie `Default`, que le sync ne
> prend **pas** — vous gardez donc les mises à jour dans leur propre bucket
> (ex. une classification `WindowsUpdate`) sans conflit. Si vous ajoutez
> `Default`, utilisez `M365_EXCLUDE` (motif egrep) pour laisser ces domaines
> CDN/MàJ dehors.

À rafraîchir en cron — le script recharge dnsteerd lui-même, et uniquement si
la liste a changé :

```sh
# /etc/cron.d/dnsteerd-m365  (quotidien)
30 4 * * *  root  /usr/local/bin/m365-sync.sh
```

En cas de changement, le script fait un reload intégré — `dnsteerd boot` puis
relance du daemon via `pkill -x dnsteerd` (son superviseur — inittab `respawn`
ou systemd `Restart=` — le relance et recharge le conf.d). Surchargez le
binaire avec `M365_DNSTEERD=/chemin/dnsteerd`, ou remplacez tout le reload via
`M365_RELOAD="systemctl restart dnsteerd"`.

Puis routez les protocoles obtenus par le lien de breakout, ex.
`ip daddr @ndpi_v4_<id Microsoft365>` / `@ndpi_v4_<id Teams>` (voir plus bas).
dnsteerd exploite les patterns **de domaine** de la liste Microsoft (il classe
la résolution DNS du client → injecte l'IP résolue) ; les plages IP que
Microsoft publie aussi ne sont pas nécessaires.

#### Intune (gestion des postes)

Intune n'est **pas** dans l'API `endpoints.office.com` (ses endpoints sont
documentaires seulement). Vérifiez d'abord si votre nDPI le classe déjà
(`dnsteerd list | grep -i intune`) — certains builds/customisations
embarquent un protocole `Intune` ; si oui, routez simplement le `@Intune`
natif, rien à ajouter.

Sinon, Microsoft recommande lui-même un catch-all par domaine, stable —
`*.manage.microsoft.com` + `manage.microsoft.com` (et `*.dm.microsoft.com`
pour Defender/EPM) — donc pas de sync nécessaire : déposez un fichier statique
dans le conf.d :

```
# protocols.d/intune.txt
host:"manage.microsoft.com",host:"dm.microsoft.com"@Intune
```

Ce catch-all couvre enrôlement, check-in, l'Intune Management Extension
(déploiement apps/scripts, dont le CDN migre vers `manage.microsoft.com`) et
Remote Help. Il n'inclut **volontairement pas** les endpoints Windows Update /
Delivery Optimization que la doc Intune liste aussi — gardez-les dans votre
bucket `WindowsUpdate`. Routez `@Intune` par le lien de breakout, comme les
protocoles M365.

## Limitations connues (assumées)

- **Extension headers IPv6 non parcourus** : un paquet DNS transporté
  dans un datagramme IPv6 à extension headers n'est pas reconnu — il
  passe non classé (fail-open). Les plateformes sans IPv6 peuvent
  compiler avec `#define DNSTEERD_IPV6 0` dans `profile.h` (pas de sets
  v6, AAAA/ipv6hint ignorés).
- **DNS UDP seulement** : le repli DNS/TCP (réponses tronquées) n'est pas
  intercepté ; rare en pratique avec EDNS0.
- **DoH/DoT invisibles** : un client qui résout en DNS chiffré ne passe
  pas par l'interception — son trafic suit la route par défaut
  (dégradation, pas de coupure). Voir [Gérer DoH/DoT](#gérer-dohdot)
  ci-dessous.
- Le re-add d'une IP déjà présente **ne rafraîchit pas** son timeout
  (comportement nf_tables) ; sans incidence dans les topologies à
  résolveur cache, dont les TTL décomptent en cascade.

## Gérer DoH/DoT

Le DNS chiffré n'est pas inspectable **par conception** : la réponse vit
dans du TLS, et la lire exigerait de terminer la session TLS (MITM avec
une CA déployée sur chaque client) — fragile, mis en échec par le
certificate pinning, et hors du périmètre d'un daemon réseau. L'approche
pratique n'est pas de déchiffrer mais de **ramener les clients vers le
Do53 en clair**, que dnsteerd voit. Les deux protocoles se traitent très
différemment :

**DoT (RFC 7858)** utilise un port dédié, **853/tcp** — trivial à
neutraliser. Bloqué ou rejeté, les clients retombent en DNS clair :

```sh
nft add rule inet matable forward tcp dport 853 reject
```

**DoH (RFC 8484)** est du HTTPS sur 443, indiscernable du web normal par
le port. Les leviers, du plus propre au plus rustique :

1. **Canary domain** : répondre NXDOMAIN pour `use-application-dns.net`
   depuis le résolveur local. Firefox interroge ce nom au démarrage et
   désactive silencieusement son DoH automatique sur NXDOMAIN. Avec
   BIND :

   ```
   zone "use-application-dns.net" { type master; file "/chemin/db.empty"; };
   ```

2. **Bloquer les résolveurs DoH connus** (dns.google,
   cloudflare-dns.com, mozilla.cloudflare-dns.com, dns.quad9.net, …)
   par set d'IPs et/ou SNI. Course sans fin, mais couvre les gros.
3. **Politique de poste** sur parc managé (GPO/MDM) : désactiver le DoH
   dans les navigateurs — le plus fiable quand on contrôle les clients.

À garder en tête : DoH/DoT n'est quasi jamais le défaut sur un poste
d'entreprise pointant l'AD/résolveur local ; et ce qui passe quand même
dégrade proprement (trafic non classé sur la route par défaut), sans
jamais rien casser.

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
