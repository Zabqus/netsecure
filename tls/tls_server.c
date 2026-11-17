/*
 * tls_server.c – serwer echo TCP + TLS (oceny 3.0 / 3.5 / 4.0).
 *
 * Uruchomienie:
 *   ./build/tls_server --cert pki/out/selfsigned/server.crt --key pki/out/selfsigned/server.key
 *   ./build/tls_server --cert pki/out/server/server.crt --key pki/out/server/server.key  (od CA)
 *   ./build/tls_server --cert ... --key ... --ca pki/out/ca/ca.crt --require-client-cert (mTLS)
 *   ./build/tls_server -6 -p 5443 --cert ... --key ... --tls13
 *
 * Przebieg:
 *   SSL_CTX (konfiguracja TLS, certyfikat + klucz, przy mTLS zaufane CA) → socket/bind/listen →
 *   pętla: accept → SSL_new + SSL_set_fd → SSL_accept (handshake, przy mTLS weryfikacja
 *   certyfikatu klienta) → SSL_read/SSL_write (echo) → SSL_shutdown → SSL_free → close
 *
 * Klienci obsługiwani są po kolei (jeden naraz).
 */
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <openssl/ssl.h>

#include "net_common.h"
#include "tls_common.h"

#define DEFAULT_PORT "5443"
#define BACKLOG      8

#define TAG "[TLS][srv]"

static volatile sig_atomic_t g_stop = 0;

static void on_sigint(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Użycie: %s [-4|-6] [-p <port>] --cert <plik> --key <plik>\n"
                    "          [--ca <plik> [--require-client-cert]] [--tls13]\n"
                    "  -4 / -6        IPv4 (domyślnie) / IPv6\n"
                    "  -p <port>      port nasłuchu (domyślnie " DEFAULT_PORT ")\n"
                    "  --cert <plik>  certyfikat serwera (PEM)\n"
                    "  --key <plik>   klucz prywatny serwera (PEM)\n"
                    "  --ca <plik>    CA, którym ufamy przy certyfikatach klientów (mTLS)\n"
                    "  --require-client-cert  odrzuć klienta bez certyfikatu\n"
                    "  --tls13        tylko TLS 1.3 (domyślnie min. TLS 1.2)\n"
                    "  --version      wersja OpenSSL\n", prog);
    exit(EXIT_FAILURE);
}

static SSL_CTX *create_context(const char *cert, const char *key, const char *ca_file,
                               int require_client_cert, int tls13_only)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL)
        tls_die("SSL_CTX_new");

    tls_ctx_harden(ctx, tls13_only);
    tls_load_cert_and_key(ctx, cert, key);

    if (ca_file != NULL) {
        // mTLS – chroni przed: dostępem nieznanych klientów; serwer prosi klienta
        // o certyfikat i sprawdza, czy podpisało go nasze CA (i czy ma clientAuth)
        int mode = SSL_VERIFY_PEER;
        if (require_client_cert)
            mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;   /* brak certyfikatu = koniec */
        SSL_CTX_set_verify(ctx, mode, NULL);

        if (!SSL_CTX_load_verify_file(ctx, ca_file))
            tls_die("nie udało się wczytać pliku --ca");

        // nazwy zaufanych CA wysyłane w CertificateRequest – podpowiedź dla klienta,
        // jaki certyfikat ma pokazać
        STACK_OF(X509_NAME) *names = SSL_load_client_CA_file(ca_file);
        if (names == NULL)
            tls_die("SSL_load_client_CA_file");
        SSL_CTX_set_client_CA_list(ctx, names);   /* kontekst przejmuje listę */
    }
    return ctx;
}

// Gniazdo nasłuchujące – jak w projekcie 1.
static int create_listen_socket(int family, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *res;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

    int rc = getaddrinfo(NULL, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        exit(EXIT_FAILURE);
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0)
        die("socket");

    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on) < 0)
        die("setsockopt(SO_REUSEADDR)");
    if (res->ai_family == AF_INET6) {
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on) < 0)
            die("setsockopt(IPV6_V6ONLY)");
    }

    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0)
        die("bind");
    freeaddrinfo(res);

    if (listen(fd, BACKLOG) < 0)
        die("listen");
    return fd;
}

// Handshake i echo z jednym klientem. Zwraca 1, jeśli sesja skończyła się poprawnie
// (wtedy wywołujący może wykonać SSL_shutdown), 0 przy błędzie.
static int serve_client(SSL *ssl, const char *peer, int mtls)
{
    // handshake TLS: ClientHello → ServerHello, certyfikat, ... → Finished
    // przy mTLS tu też klient przesyła swój certyfikat, a OpenSSL go weryfikuje
    int ret = SSL_accept(ssl);
    if (ret <= 0) {
        fprintf(stderr, "%s handshake z %s nieudany\n", TAG, peer);
        long v = SSL_get_verify_result(ssl);   /* przy mTLS: dlaczego odrzucono certyfikat */
        if (v != X509_V_OK)
            fprintf(stderr, "%s weryfikacja certyfikatu klienta: %s\n",
                    TAG, X509_verify_cert_error_string(v));
        tls_report_error(ssl, ret, TAG);
        return 0;   /* sesji TLS nie było, więc nie ma czego zamykać przez SSL_shutdown */
    }
    tls_print_session(ssl, TAG);

    if (mtls) {
        // tu certyfikat (jeśli jest) został już pozytywnie zweryfikowany przez OpenSSL
        tls_print_peer_cert(ssl, TAG);
        if (SSL_get0_peer_certificate(ssl) != NULL)
            printf("%s klient %s uwierzytelniony certyfikatem (mTLS)\n", TAG, peer);
    }

    char buf[MAX_MSG];
    while (!g_stop) {
        // odczyt ograniczony rozmiarem bufora – dłuższa wiadomość przyjdzie w kilku częściach
        int n = SSL_read(ssl, buf, sizeof buf);
        if (n <= 0)
            return tls_report_error(ssl, n, TAG);

        printf("%s %d B od %s: \"", TAG, n, peer);
        print_safe(buf, text_len(buf, (size_t)n));
        printf("\"\n");

        // w trybie blokującym SSL_write wysyła wszystko albo zwraca błąd
        ret = SSL_write(ssl, buf, n);
        if (ret <= 0)
            return tls_report_error(ssl, ret, TAG);
    }
    return 0;
}

static void handle_client(SSL_CTX *ctx, int cfd, const char *peer, int mtls)
{
    set_socket_timeouts(cfd, IO_TIMEOUT_SEC);

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "%s SSL_new nie powiodło się\n", TAG);
        return;
    }
    // OpenSSL dostaje nasze gotowe gniazdo TCP – TLS działa nad naszą warstwą 4
    SSL_set_fd(ssl, cfd);

    if (serve_client(ssl, peer, mtls)) {
        // odsyłamy własne close_notify (po błędzie fatalnym tego robić nie wolno)
        SSL_shutdown(ssl);
    }
    SSL_free(ssl);
}

int main(int argc, char *argv[])
{
    int family = AF_INET;
    const char *port = DEFAULT_PORT;
    const char *cert = NULL;
    const char *key = NULL;
    const char *ca_file = NULL;
    int require_client_cert = 0;
    int tls13_only = 0;

    for (int i = 1; i < argc; i++) {
        int f = parse_family(argv[i]);
        if (f != -1)
            family = f;
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
            port = argv[++i];
        else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc)
            cert = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
            key = argv[++i];
        else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc)
            ca_file = argv[++i];
        else if (strcmp(argv[i], "--require-client-cert") == 0)
            require_client_cert = 1;
        else if (strcmp(argv[i], "--tls13") == 0)
            tls13_only = 1;
        else if (strcmp(argv[i], "--version") == 0) {
            tls_print_version("tls_server");
            return 0;
        } else
            usage(argv[0]);
    }
    if (cert == NULL || key == NULL)
        usage(argv[0]);
    if (require_client_cert && ca_file == NULL) {
        fprintf(stderr, "%s --require-client-cert wymaga --ca <plik>\n", TAG);
        return EXIT_FAILURE;
    }

    setvbuf(stdout, NULL, _IOLBF, 0);

    // Ctrl+C bez SA_RESTART – accept()/SSL_read() przerwą się i serwer się zamknie
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigint;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) < 0)
        die("sigaction");

    // chroni przed: zabiciem serwera sygnałem SIGPIPE przy zapisie do zamkniętego połączenia
    signal(SIGPIPE, SIG_IGN);

    check_key_permissions(key, TAG);
    SSL_CTX *ctx = create_context(cert, key, ca_file, require_client_cert, tls13_only);

    int lfd = create_listen_socket(family, port);

    struct sockaddr_storage local;
    socklen_t local_len = sizeof local;
    char addr[ADDR_STR_LEN];
    if (getsockname(lfd, (struct sockaddr *)&local, &local_len) < 0)
        die("getsockname");
    printf("%s nasłuchuję na %s (min. %s, Ctrl+C kończy)\n", TAG,
           addr_to_str((struct sockaddr *)&local, local_len, addr, sizeof addr),
           tls13_only ? "TLS 1.3" : "TLS 1.2");
    if (ca_file != NULL)
        printf("%s mTLS: certyfikat klienta %s, zaufane CA: %s\n", TAG,
               require_client_cert ? "WYMAGANY" : "opcjonalny", ca_file);

    while (!g_stop) {
        struct sockaddr_storage peer;
        socklen_t peer_len = sizeof peer;
        int cfd = accept(lfd, (struct sockaddr *)&peer, &peer_len);
        if (cfd < 0) {
            if (errno != EINTR)
                perror("accept");
            continue;
        }

        addr_to_str((struct sockaddr *)&peer, peer_len, addr, sizeof addr);
        printf("%s połączenie TCP od %s\n", TAG, addr);

        handle_client(ctx, cfd, addr, ca_file != NULL);
        close(cfd);
        printf("%s koniec sesji z %s\n", TAG, addr);
    }

    printf("\n%s zamykam serwer\n", TAG);
    close(lfd);
    SSL_CTX_free(ctx);
    return 0;
}
