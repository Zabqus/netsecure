/*
 * tls_common.h – wspólne funkcje pomocnicze związane z OpenSSL.
 * Implementacja w tls_common.c (część biblioteki statycznej "netcommon").
 *
 * Etap 1: tylko wypis wersji. W kolejnych etapach dojdą: tls_die, tls_print_peer_cert,
 * tls_print_session, print_safe.
 */
#ifndef TLS_COMMON_H
#define TLS_COMMON_H

// Wypisuje wersję OpenSSL: z nagłówków (czas kompilacji) i z biblioteki (czas działania).
void tls_print_version(const char *prog);

#endif /* TLS_COMMON_H */
