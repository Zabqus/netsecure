/*
 * tls_common.h – wspólne funkcje pomocnicze związane z OpenSSL.
 * Implementacja w tls_common.c (część biblioteki statycznej "netcommon").
 */
#ifndef TLS_COMMON_H
#define TLS_COMMON_H

#include <stddef.h>
#include <openssl/ssl.h>

// Maksymalny rozmiar jednej wiadomości (bufory w kliencie i serwerze mają stały rozmiar).
#define MAX_MSG 4096

// Timeout operacji na gnieździe w sekundach (obejmuje też handshake TLS).
#define IO_TIMEOUT_SEC 30

// Wypisuje wersję OpenSSL: z nagłówków (kompilacja) i z biblioteki (działanie).
void tls_print_version(const char *prog);

// Wypisuje komunikat i błędy z kolejki OpenSSL, kończy program.
_Noreturn void tls_die(const char *msg);

// Ustawia minimalną wersję protokołu i wyłącza kompresję – wspólne dla klienta i serwera.
void tls_ctx_harden(SSL_CTX *ctx, int tls13_only);

// Kończy program, jeśli plik klucza prywatnego jest dostępny dla innych niż właściciel.
void check_key_permissions(const char *path, const char *tag);

// Wczytuje certyfikat i klucz prywatny do kontekstu i sprawdza, czy do siebie pasują.
void tls_load_cert_and_key(SSL_CTX *ctx, const char *cert, const char *key);

// Ustawia timeout odczytu i zapisu na gnieździe.
void set_socket_timeouts(int fd, int seconds);

// Wersja protokołu, szyfr, grupa wymiany klucza.
void tls_print_session(SSL *ssl, const char *tag);

// Subject, issuer, ważność certyfikatu drugiej strony i wynik jego weryfikacji.
void tls_print_peer_cert(SSL *ssl, const char *tag);

// Tłumaczy wynik nieudanego SSL_read/SSL_write/SSL_accept/SSL_connect na komunikat.
// Zwraca 1, gdy wolno jeszcze wywołać SSL_shutdown() (druga strona wysłała close_notify
// albo minął timeout); 0 po błędzie fatalnym (SSL_ERROR_SSL/SYSCALL – bez SSL_shutdown).
int tls_report_error(SSL *ssl, int ret, const char *tag);

// Bezpieczne wypisanie danych od peera: znaki niedrukowalne jako \xNN.
void print_safe(const char *buf, size_t len);

#endif /* TLS_COMMON_H */
