/*
 * tls_common.c – implementacja helperów OpenSSL (opis w tls_common.h).
 */
#include "tls_common.h"

#include <stdio.h>
#include <openssl/crypto.h>     /* OpenSSL_version */
#include <openssl/opensslv.h>   /* OPENSSL_VERSION_TEXT */

void tls_print_version(const char *prog)
{
    printf("%s\n", prog);

    // OPENSSL_VERSION_TEXT to stała z nagłówków – wersja, z którą program był KOMPILOWANY
    printf("  nagłówki OpenSSL (kompilacja): %s\n", OPENSSL_VERSION_TEXT);

    // OpenSSL_version() pyta bibliotekę libcrypto załadowaną TERAZ, w czasie działania.
    // Obie wersje powinny się zgadzać – jeśli nie, system ma inną bibliotekę niż nagłówki.
    printf("  biblioteka OpenSSL (działanie): %s\n", OpenSSL_version(OPENSSL_VERSION));
}
