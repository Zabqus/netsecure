#!/usr/bin/env bash
# pki_show.sh – podgląd certyfikatu i (opcjonalnie) weryfikacja względem zaufanego CA.
#
# Użycie: bash scripts/pki_show.sh <certyfikat.crt> [zaufane_ca.crt]
#   bash scripts/pki_show.sh pki/out/selfsigned/server.crt
#   bash scripts/pki_show.sh pki/out/selfsigned/server.crt pki/out/selfsigned/server.crt

set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "Użycie: $0 <certyfikat.crt> [zaufane_ca.crt]" >&2
    exit 1
fi

CERT="$1"

echo "=== Najważniejsze pola ==="
openssl x509 -in "$CERT" -noout -subject -issuer -dates -fingerprint -sha256 \
    -ext subjectAltName,basicConstraints,keyUsage,extendedKeyUsage

echo
echo "=== Pełna zawartość (openssl x509 -text) ==="
openssl x509 -in "$CERT" -noout -text

if [ $# -eq 2 ]; then
    echo
    echo "=== Weryfikacja łańcucha zaufania ==="
    openssl verify -CAfile "$2" "$CERT"
fi
