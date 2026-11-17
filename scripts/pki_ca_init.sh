#!/usr/bin/env bash
# pki_ca_init.sh – tworzy własne CA: klucz EC P-256 + certyfikat self-signed (ocena 3.5).
#
# Użycie: bash scripts/pki_ca_init.sh        (tylko na net-server!)
# Wynik:  pki/out/ca/ca.key (600) – NIGDY nie opuszcza serwera
#         pki/out/ca/ca.crt       – kopiujemy na klienta jako --ca

set -euo pipefail
cd "$(dirname "$0")/.."

OUT=pki/out/ca
DAYS=365

# nadpisanie CA unieważnia wszystkie wystawione wcześniej certyfikaty
if [ -e "$OUT/ca.key" ]; then
    read -r -p "CA już istnieje ($OUT/ca.key). Nadpisanie unieważni wszystkie certyfikaty. Nadpisać? [t/N] " answer
    if [ "$answer" != "t" ]; then
        echo "Przerwano."
        exit 1
    fi
fi

mkdir -p "$OUT"
chmod 700 pki/out "$OUT"
umask 077

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$OUT/ca.key"

openssl req -x509 -new -key "$OUT/ca.key" -config pki/ca.cnf \
    -days "$DAYS" -sha256 -out "$OUT/ca.crt"

chmod 600 "$OUT/ca.key"
chmod 644 "$OUT/ca.crt"

echo
echo "CA gotowe:"
ls -l "$OUT"
echo
echo "Na klienta kopiujemy TYLKO ca.crt, np.:"
echo "  scp $OUT/ca.crt student@192.168.1.202:netsecure/pki/out/ca/"
