#!/usr/bin/env bash
# pki_issue.sh – wystawia certyfikat podpisany przez CA (oceny 3.5 / 4.0).
#
# Użycie:
#   bash scripts/pki_issue.sh server            → pki/out/server/server.{key,crt}
#   bash scripts/pki_issue.sh client <nazwa>    → pki/out/<nazwa>/<nazwa>.{key,crt}, CN=<nazwa>
#   bash scripts/pki_issue.sh rogue             → obce CA (pki/out/rogue-ca) + certyfikat klienta
#                                                 pki/out/rogue-client – do testu odrzucenia
#
# Kroki: klucz → CSR (wniosek: klucz publiczny + nazwa) → CA podpisuje CSR
#        i nadaje rozszerzenia z pliku .cnf → weryfikacja względem certyfikatu CA

set -euo pipefail
cd "$(dirname "$0")/.."

DAYS=90

usage() {
    echo "Użycie: $0 server | client <nazwa> | rogue" >&2
    exit 1
}

[ $# -ge 1 ] || usage

case "$1" in
    server)
        [ $# -eq 1 ] || usage
        NAME=server
        CNF=pki/server.cnf
        SUBJ="/O=netsecure/CN=net-server"
        CA=pki/out/ca
        ;;
    client)
        [ $# -eq 2 ] || usage
        NAME="$2"
        # nazwa trafia do ścieżki pliku i do CN – tylko bezpieczne znaki (bez "/", "..", spacji)
        if ! [[ "$NAME" =~ ^[A-Za-z0-9_-]+$ ]]; then
            echo "Nazwa klienta może zawierać tylko litery, cyfry, '_' i '-'" >&2
            exit 1
        fi
        CNF=pki/client.cnf
        SUBJ="/O=netsecure/CN=$NAME"
        CA=pki/out/ca
        ;;
    rogue)
        [ $# -eq 1 ] || usage
        NAME=rogue-client
        CNF=pki/client.cnf
        SUBJ="/O=netsecure/CN=rogue-client"
        CA=pki/out/rogue-ca
        ;;
    *)
        usage
        ;;
esac

mkdir -p pki/out
chmod 700 pki/out
umask 077

# Obce CA – celowo z TAKĄ SAMĄ nazwą jak nasze (ca.cnf), ale z innym kluczem.
# Pokazuje, że serwer sprawdza podpis, a nie nazwę wystawcy.
if [ "$1" = rogue ] && [ ! -e "$CA/ca.key" ]; then
    mkdir -p "$CA"
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$CA/ca.key"
    openssl req -x509 -new -key "$CA/ca.key" -config pki/ca.cnf -days 365 -sha256 -out "$CA/ca.crt"
fi

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

# 1. klucz prywatny – powstaje u właściciela i nigdzie nie jest wysyłany
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$OUT/$NAME.key"

# 2. CSR – wniosek o certyfikat, podpisany kluczem właściciela (dowód posiadania klucza)
openssl req -new -key "$OUT/$NAME.key" -config "$CNF" -subj "$SUBJ" -out "$OUT/$NAME.csr"

# 3. CA podpisuje wniosek. Rozszerzenia (SAN, keyUsage, ...) bierze z SWOJEGO pliku .cnf,
#    a nie z CSR – to CA decyduje, do czego certyfikat może służyć.
#    ca.srl przechowuje kolejny numer seryjny (każdy certyfikat od CA ma unikalny).
openssl x509 -req -in "$OUT/$NAME.csr" \
    -CA "$CA/ca.crt" -CAkey "$CA/ca.key" -CAserial "$CA/ca.srl" -CAcreateserial \
    -extfile "$CNF" -extensions ext \
    -days "$DAYS" -sha256 -out "$OUT/$NAME.crt"

chmod 600 "$OUT/$NAME.key"
chmod 644 "$OUT/$NAME.crt"

# 4. sprawdzenie, czy certyfikat poprawnie łączy się z CA
openssl verify -CAfile "$CA/ca.crt" "$OUT/$NAME.crt"

echo
ls -l "$OUT"
