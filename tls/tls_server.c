/*
 * tls_server.c – serwer echo TCP + TLS (oceny 3.0 / 3.5 / 4.0).
 *
 * Etap 1 (szkielet): program sprawdza tylko, że projekt kompiluje się i linkuje z OpenSSL.
 *   ./build/tls_server --version
 *
 * Docelowo (etap 3+):
 *   tls_server [-4|-6] [-p 5443] --cert <plik> --key <plik>
 *              [--ca <ca.crt> --require-client-cert] [--tls13]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>      /* strcmp */

#include "tls_common.h"

int main(int argc, char *argv[])
{
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        tls_print_version("tls_server");
        return 0;
    }

    fprintf(stderr, "Użycie: %s --version\n"
                    "(etap 1 – szkielet; serwer TLS powstanie w etapie 3)\n", argv[0]);
    return EXIT_FAILURE;
}
