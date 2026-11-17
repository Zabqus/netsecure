#!/usr/bin/env bash
# pki_issue.sh – wystawia certyfikat podpisany przez nasze CA (ocena 3.5).
#
# Użycie: bash scripts/pki_issue.sh server
# Wynik:  pki/out/server/server.key (600), server.csr, server.crt
#
# Kroki: klucz → CSR (wniosek: klucz publiczny + nazwa) → CA podpisuje CSR
#        i nadaje rozszerzenia z pliku .cnf → weryfikacja względem ca.crt

set -euo pipefail
cd "$(dirname "$0")/.."

CA=pki/out/ca
DAYS=90

usage() {
    echo "Użycie: $0 server" >&2
    exit 1
}

[ $# -eq 1 ] || usage

case "$1" in
    server)
        NAME=server
        CNF=pki/server.cnf
        ;;
    *)
        usage
        ;;
esac

if [ ! -e "$CA/ca.key" ]; then
    echo "Brak CA – najpierw: bash scripts/pki_ca_init.sh" >&2
    exit 1
fi

OUT=pki/out/$NAME
if [ -e "$OUT/$NAME.key" ]; then
    read -r -p "Plik $OUT/$NAME.key już istnieje. Nadpisać? [t/N] " answer
    if [ "$answer" != "t" ]; then
        echo "Przerwano."
        exit 1
    fi
fi

mkdir -p "$OUT"
chmod 700 "$OUT"
umask 077

# 1. klucz prywatny – powstaje u właściciela i nigdzie nie jest wysyłany
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$OUT/$NAME.key"

# 2. CSR – wniosek o certyfikat, podpisany kluczem właściciela (dowód posiadania klucza)
openssl req -new -key "$OUT/$NAME.key" -config "$CNF" -out "$OUT/$NAME.csr"

# 3. CA podpisuje wniosek. Rozszerzenia (SAN, keyUsage, ...) bierze z SWOJEGO pliku .cnf,
#    a nie z CSR – to CA decyduje, do czego certyfikat może służyć.
#    ca.srl przechowuje kolejny numer seryjny (każdy certyfikat od CA ma unikalny).
openssl x509 -req -in "$OUT/$NAME.csr" \
    -CA "$CA/ca.crt" -CAkey "$CA/ca.key" -CAserial "$CA/ca.srl" -CAcreateserial \
    -extfile "$CNF" -extensions ext \
    -days "$DAYS" -sha256 -out "$OUT/$NAME.crt"

chmod 600 "$OUT/$NAME.key"
chmod 644 "$OUT/$NAME.crt"

# 4. sprawdzenie, czy certyfikat poprawnie łączy się z naszym CA
openssl verify -CAfile "$CA/ca.crt" "$OUT/$NAME.crt"

echo
ls -l "$OUT"
