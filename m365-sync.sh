#!/bin/sh
# m365-sync.sh — synchronise les domaines Microsoft 365 (liste officielle
# Microsoft) en protocoles custom nDPI, pour le routage applicatif dnsteerd
# (ex. local breakout : sortir M365 par une ligne FTTH dédiée).
#
# Source : https://endpoints.office.com (API officielle, mise à jour par MS).
# Sortie : un fichier nDPI custom-protocols déposé dans le conf.d de dnsteerd
#          (CUSTOM_PROTOS_DIR), chargé EN PLUS du custom_protocols principal —
#          donc indépendant de toute régénération de ce dernier.
#
# Idempotent : interroge d'abord /version ; si la liste n'a pas changé depuis
# le dernier run, ne fait rien (exit 2). Sinon régénère le fichier (exit 0).
# Échec réseau / liste vide → conserve le fichier précédent (exit 1).
#
# Régénération automatique : à lancer en cron (cf. README, section M365).
set -eu

# Dependances requises : curl + jq. Sans ce controle, leur absence se traduit
# par une sortie vide silencieuse (les pipes plus bas redirigent stderr) et le
# message trompeur « recuperation vide ». On echoue clairement a la place.
for _bin in curl jq; do
    command -v "$_bin" >/dev/null 2>&1 || {
        echo "m365-sync: dependance manquante : '$_bin' introuvable dans le PATH" >&2
        exit 1
    }
done

# ---- Configuration (surchargeable par l'environnement) ----------------------
# OUT doit pointer dans le CUSTOM_PROTOS_DIR de votre build dnsteerd
# (défaut /etc/dnsteerd/protocols.d) ; adaptez M365_OUT si votre intégration
# utilise un autre répertoire.
GUID="${M365_GUID:-b10c5ed1-bad1-445f-b386-b919946339a7}"   # clientrequestid stable
OUT="${M365_OUT:-/etc/dnsteerd/protocols.d/microsoft365.txt}"
CACHE="${M365_CACHE:-/etc/dnsteerd/protocols.d/.m365.version}"
CATEGORIES="${M365_CATEGORIES:-Optimize,Allow}"   # catégories MS retenues (breakout)
# Regex (egrep) de domaines à EXCLURE — pour ne pas réinjecter ici ce que vous
# classez ailleurs (ex. CDN/MàJ Office forcés dans WindowsUpdate). Vide par
# défaut : la catégorie Default (où vit tout le CDN/update Office) n'est de
# toute façon pas prise ci-dessus. À renseigner si vous ajoutez 'Default'.
EXCLUDE="${M365_EXCLUDE:-}"
# Reload dnsteerd après une MAJ effective (uniquement si la liste a changé).
# DNSTEERD = binaire (PATH ou chemin complet). M365_RELOAD = commande de reload
# personnalisée (ex. "systemctl restart dnsteerd") ; vide → reload générique
# intégré (boot + relance du daemon par pkill, fonctionne avec inittab respawn
# comme avec systemd Restart=, sans dépendre d'un pidfile).
DNSTEERD="${M365_DNSTEERD:-dnsteerd}"
BASE="https://endpoints.office.com"

# Mappe une serviceArea Microsoft -> nom de protocole nDPI (augmente les protos
# host existants, donc routables tels quels). Éditez pour regrouper autrement
# (ex. tout vers "Microsoft365" pour une seule route de breakout).
map_proto() {
    case "$1" in
        Exchange)   echo "Outlook" ;;
        SharePoint) echo "MS_OneDrive" ;;   # nDPI regroupe SharePoint+OneDrive ici
        Skype)      echo "Teams" ;;
        *)          echo "Microsoft365" ;;   # Common + tout le reste
    esac
}
# -----------------------------------------------------------------------------

force=0
[ "${1:-}" = "--force" ] && force=1

# 1) Détection de changement via /version (évite fetch + reload inutiles)
latest=$(curl -fsS "$BASE/version/worldwide?clientrequestid=$GUID" 2>/dev/null \
         | jq -r '.latest' 2>/dev/null || true)
if [ -n "$latest" ] && [ "$force" -eq 0 ] && [ -f "$CACHE" ] \
   && [ "$latest" = "$(cat "$CACHE" 2>/dev/null)" ]; then
    exit 2   # rien de neuf
fi

# 2) Récupération + extraction (serviceArea <TAB> domaine), catégories filtrées
lines=$(curl -fsS "$BASE/endpoints/worldwide?clientrequestid=$GUID" 2>/dev/null \
        | jq -r --arg cats "$CATEGORIES" '
            ($cats | split(",")) as $cl
            | .[]
            | select(.category as $c | $cl | index($c))
            | select(.urls)
            | .serviceArea as $sa | .urls[] | "\($sa)\t\(.)"
          ' 2>/dev/null || true)

if [ -z "$lines" ]; then
    echo "m365-sync: récupération vide/échec (réseau ? format MS ?) — fichier conservé" >&2
    exit 1
fi

# 3) serviceArea->proto, retrait du joker *., dédup, regroupement par protocole
exclude_filter() { if [ -n "$EXCLUDE" ]; then grep -vE "$EXCLUDE"; else cat; fi; }

body=$(printf '%s\n' "$lines" | while IFS="$(printf '\t')" read -r sa url; do
           [ -n "$url" ] || continue
           printf '%s\t%s\n' "$(map_proto "$sa")" "${url#\*.}"
       done | sort -u | exclude_filter | awk -F'\t' '
           { h[$1] = h[$1] (h[$1] ? "," : "") "host:\"" $2 "\"" }
           END { for (p in h) print h[p] "@" p }
       ')

[ -n "$body" ] || { echo "m365-sync: 0 domaine après mapping — abandon" >&2; exit 1; }

# 4) Écriture atomique (un échec ne corrompt pas le fichier en place)
mkdir -p "$(dirname "$OUT")"
{
    echo "# Microsoft 365 — généré par m365-sync.sh, NE PAS ÉDITER À LA MAIN."
    echo "# Source: $BASE  version: ${latest:-?}  $(date -u +%FT%TZ)  catégories: $CATEGORIES"
    printf '%s\n' "$body"
} > "$OUT.tmp" && mv "$OUT.tmp" "$OUT"

[ -n "$latest" ] && printf '%s\n' "$latest" > "$CACHE"

echo "m365-sync: $(printf '%s\n' "$body" | wc -l) protocole(s) M365 -> $OUT (version ${latest:-?})"

# 5) Reload dnsteerd (liste changée). Personnalisé via M365_RELOAD, sinon
#    reload générique : boot (sets/JSON à jour) puis relance du daemon — son
#    superviseur (inittab respawn / systemd Restart) le redémarre, et il
#    recharge alors le conf.d donc les nouveaux domaines.
if [ -n "${M365_RELOAD:-}" ]; then
    eval "$M365_RELOAD"
else
    "$DNSTEERD" boot >/dev/null 2>&1 || true
    pkill -x dnsteerd 2>/dev/null || true
fi

exit 0
