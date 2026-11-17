/*
 * tls_client.c – klient echo TCP + TLS (oceny 3.0 / 3.5 / 4.0).
 *
 * Etap 1 (szkielet): program sprawdza tylko, że projekt kompiluje się i linkuje z OpenSSL.
 *   ./build/tls_client --version
 *
 * Docelowo (etap 3+):
 *   tls_client -h <host> [-p 5443] (--ca <ca.crt> | --insecure) [--cert <plik> --key <plik>]
 *              [--name <nazwa_w_cert>] [--tls13] [-m "wiadomość"]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>      /* strcmp */

#include "tls_common.h"

int main(int argc, char *argv[])
{
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        tls_print_version("tls_client");
        return 0;
    }

    fprintf(stderr, "Użycie: %s --version\n"
                    "(etap 1 – szkielet; klient TLS powstanie w etapie 3)\n", argv[0]);
    return EXIT_FAILURE;
}
