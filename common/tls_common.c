/*
 * tls_common.c – implementacja helperów OpenSSL (opis w tls_common.h).
 */
#include "tls_common.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/x509.h>

void tls_print_version(const char *prog)
{
    printf("%s\n", prog);
    // stała z nagłówków = wersja z czasu kompilacji; funkcja = biblioteka załadowana teraz
    printf("  nagłówki OpenSSL (kompilacja): %s\n", OPENSSL_VERSION_TEXT);
    printf("  biblioteka OpenSSL (działanie): %s\n", OpenSSL_version(OPENSSL_VERSION));
}

void tls_die(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    // szczegóły błędów tylko lokalnie – drugiej stronie niczego nie wysyłamy
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

void tls_ctx_harden(SSL_CTX *ctx, int tls13_only)
{
    // chroni przed: downgrade do starych, podatnych wersji (SSLv3, TLS 1.0, TLS 1.1)
    int min = tls13_only ? TLS1_3_VERSION : TLS1_2_VERSION;
    if (!SSL_CTX_set_min_proto_version(ctx, min))
        tls_die("SSL_CTX_set_min_proto_version");

    // chroni przed: atakiem CRIME (odzyskiwanie sekretów z długości skompresowanych danych);
    // w OpenSSL 3.x kompresja i tak jest domyślnie wyłączona – ustawiamy jawnie
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

    // Listy szyfrów nie ustawiamy: domyślne w OpenSSL 3.5 są bezpieczne (AEAD, ECDHE).
}

void check_key_permissions(const char *path, const char *tag)
{
    // chroni przed: wyciekiem klucza prywatnego przez złe uprawnienia pliku –
    // program nie startuje, jeśli klucz może czytać ktoś poza właścicielem
    struct stat st;
    if (stat(path, &st) < 0) {
        perror(path);
        exit(EXIT_FAILURE);
    }
    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        fprintf(stderr, "%s plik klucza %s ma zbyt szerokie uprawnienia (%03o), "
                        "wymagane 600: chmod 600 %s\n",
                tag, path, (unsigned)(st.st_mode & 0777), path);
        exit(EXIT_FAILURE);
    }
}

void tls_load_cert_and_key(SSL_CTX *ctx, const char *cert, const char *key)
{
    // *_chain_file: plik może zawierać też certyfikaty pośrednie
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) <= 0)
        tls_die("nie udało się wczytać certyfikatu");
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0)
        tls_die("nie udało się wczytać klucza prywatnego");

    // chroni przed: użyciem klucza, który nie pasuje do certyfikatu
    if (!SSL_CTX_check_private_key(ctx))
        tls_die("klucz prywatny nie pasuje do certyfikatu");
}

void set_socket_timeouts(int fd, int seconds)
{
    // chroni przed: klientem/serwerem, który połączy się i nic nie wysyła – blokujące
    // recv()/send() (a więc i SSL_accept/SSL_read) wracają z błędem po zadanym czasie
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0)
        perror("setsockopt(SO_RCVTIMEO)");
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) < 0)
        perror("setsockopt(SO_SNDTIMEO)");
}

void tls_print_session(SSL *ssl, const char *tag)
{
    const char *group = SSL_get0_group_name(ssl);   /* wymiana klucza (ECDHE / hybryda PQ) */

    printf("%s sesja: %s, szyfr %s, wymiana klucza %s\n", tag,
           SSL_get_version(ssl), SSL_get_cipher(ssl), group != NULL ? group : "?");
}

void tls_print_peer_cert(SSL *ssl, const char *tag)
{
    // get1 – dostajemy własną referencję, trzeba ją zwolnić przez X509_free
    X509 *cert = SSL_get1_peer_certificate(ssl);
    if (cert == NULL) {
        printf("%s druga strona nie przesłała certyfikatu\n", tag);
        return;
    }

    // XN_FLAG_ONELINE: "CN = net-server"; znaki sterujące w nazwie są escapowane
    printf("%s certyfikat peera:\n", tag);
    printf("    subject:  ");
    X509_NAME_print_ex_fp(stdout, X509_get_subject_name(cert), 0, XN_FLAG_ONELINE);
    printf("\n    issuer:   ");
    X509_NAME_print_ex_fp(stdout, X509_get_issuer_name(cert), 0, XN_FLAG_ONELINE);

    BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (out != NULL) {
        BIO_printf(out, "\n    ważny od: ");
        ASN1_TIME_print(out, X509_get0_notBefore(cert));
        BIO_printf(out, "\n    ważny do: ");
        ASN1_TIME_print(out, X509_get0_notAfter(cert));
        BIO_printf(out, "\n");
        BIO_free(out);
    }

    long v = SSL_get_verify_result(ssl);
    printf("    weryfikacja: %s\n", X509_verify_cert_error_string(v));

    X509_free(cert);
}

int tls_report_error(SSL *ssl, int ret, const char *tag)
{
    int err = SSL_get_error(ssl, ret);

    switch (err) {
    case SSL_ERROR_ZERO_RETURN:
        // druga strona wysłała close_notify – poprawne zakończenie sesji TLS
        printf("%s druga strona zamknęła połączenie (close_notify)\n", tag);
        return 1;

    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        // na blokującym gnieździe zdarza się to, gdy minie SO_RCVTIMEO/SO_SNDTIMEO
        // (recv zwraca EAGAIN) albo gdy operację przerwał sygnał (Ctrl+C)
        // to nie jest błąd fatalny, więc możemy poprawnie zakończyć sesję (close_notify)
        printf("%s brak odpowiedzi w ciągu %d s (timeout) lub przerwanie\n",
               tag, IO_TIMEOUT_SEC);
        return 1;

    case SSL_ERROR_SYSCALL:
        // błąd warstwy niżej (np. ECONNRESET – połączenie zresetowane)
        fprintf(stderr, "%s błąd gniazda: %s\n", tag, errno != 0 ? strerror(errno) : "EOF");
        ERR_print_errors_fp(stderr);
        return 0;

    case SSL_ERROR_SSL:
        // chroni przed: atakiem obcięcia (truncation) – koniec TCP bez close_notify
        // OpenSSL 3.x zgłasza jako błąd, więc nie pomylimy go z poprawnym końcem danych
        if (ERR_GET_REASON(ERR_peek_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING)
            fprintf(stderr, "%s połączenie zerwane bez close_notify (możliwe obcięcie danych)\n", tag);
        else
            fprintf(stderr, "%s błąd protokołu TLS:\n", tag);
        ERR_print_errors_fp(stderr);
        return 0;

    default:
        fprintf(stderr, "%s nieoczekiwany błąd SSL_get_error = %d\n", tag, err);
        ERR_print_errors_fp(stderr);
        return 0;
    }
}

void print_safe(const char *buf, size_t len)
{
    // chroni przed: wstrzyknięciem sekwencji sterujących terminala (np. ESC[2J) do logów –
    // wypisujemy tylko drukowalne ASCII, resztę jako \xNN
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c >= 0x20 && c <= 0x7e)
            putchar(c);
        else
            printf("\\x%02x", c);
    }
}
