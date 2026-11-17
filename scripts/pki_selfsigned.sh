#!/usr/bin/env bash
# pki_selfsigned.sh – klucz EC P-256 + certyfikat self-signed serwera (ocena 3.0).
#
# Użycie: bash scripts/pki_selfsigned.sh
# Wynik:  pki/out/selfsigned/server.key (600), pki/out/selfsigned/server.crt
#
# Na kliencie potrzebny jest tylko server.crt (jako --ca), np.:
#   scp pki/out/selfsigned/server.crt student@192.168.1.202:~/netsecure/pki/out/selfsigned/

set -euo pipefail
cd "$(dirname "$0")/.."

OUT=pki/out/selfsigned
DAYS=30

if [ -e "$OUT/server.key" ]; then
    read -r -p "Plik $OUT/server.key już istnieje. Nadpisać? [t/N] " answer
    if [ "$answer" != "t" ]; then
        echo "Przerwano."
        exit 1
    fi
fi

# 700 – katalog z kluczami widzi tylko właściciel; umask 077 – nowe pliki będą 600
mkdir -p "$OUT"
chmod 700 pki/out "$OUT"
umask 077

# 1. klucz prywatny: krzywa eliptyczna P-256 (krótszy i szybszy od RSA przy tym samym poziomie)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$OUT/server.key"

# 2. certyfikat podpisany własnym kluczem (-x509 = zamiast CSR od razu certyfikat)
openssl req -x509 -new -key "$OUT/server.key" -config pki/selfsigned.cnf \
    -days "$DAYS" -sha256 -out "$OUT/server.crt"

chmod 600 "$OUT/server.key"
chmod 644 "$OUT/server.crt"

echo
echo "Gotowe:"
ls -l "$OUT"
echo
echo "Podgląd: bash scripts/pki_show.sh $OUT/server.crt"
