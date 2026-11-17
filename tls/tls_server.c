/*
 * tls_server.c – serwer echo TCP + TLS (oceny 3.0 / 3.5).
 *
 * Uruchomienie:
 *   ./build/tls_server --cert pki/out/selfsigned/server.crt --key pki/out/selfsigned/server.key
 *   ./build/tls_server --cert pki/out/server/server.crt --key pki/out/server/server.key  (od CA)
 *   ./build/tls_server -6 -p 5443 --cert ... --key ... --tls13
 *
 * Przebieg:
 *   SSL_CTX (konfiguracja TLS, certyfikat + klucz) → socket/bind/listen →
 *   pętla: accept → SSL_new + SSL_set_fd → SSL_accept (handshake) →
 *   SSL_read/SSL_write (echo) → SSL_shutdown → SSL_free → close
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
#include <sys/stat.h>

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
    fprintf(stderr, "Użycie: %s [-4|-6] [-p <port>] --cert <plik> --key <plik> [--tls13]\n"
                    "  -4 / -6        IPv4 (domyślnie) / IPv6\n"
                    "  -p <port>      port nasłuchu (domyślnie " DEFAULT_PORT ")\n"
                    "  --cert <plik>  certyfikat serwera (PEM)\n"
                    "  --key <plik>   klucz prywatny serwera (PEM)\n"
                    "  --tls13        tylko TLS 1.3 (domyślnie min. TLS 1.2)\n"
                    "  --version      wersja OpenSSL\n", prog);
    exit(EXIT_FAILURE);
}

// chroni przed: wyciekiem klucza prywatnego przez złe uprawnienia pliku –
// serwer nie startuje, jeśli klucz może czytać ktoś poza właścicielem
static void check_key_permissions(const char *path)
{
    struct stat st;
    if (stat(path, &st) < 0)
        die(path);
    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        fprintf(stderr, "%s plik klucza %s ma zbyt szerokie uprawnienia (%03o), "
                        "wymagane 600: chmod 600 %s\n",
                TAG, path, (unsigned)(st.st_mode & 0777), path);
        exit(EXIT_FAILURE);
    }
}

static SSL_CTX *create_context(const char *cert, const char *key, int tls13_only)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL)
        tls_die("SSL_CTX_new");

    tls_ctx_harden(ctx, tls13_only);

    // *_chain_file: plik może zawierać też certyfikaty pośrednie (przydatne przy CA)
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) <= 0)
        tls_die("nie udało się wczytać certyfikatu");
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0)
        tls_die("nie udało się wczytać klucza prywatnego");

    // chroni przed: uruchomieniem z kluczem, który nie pasuje do certyfikatu
    if (!SSL_CTX_check_private_key(ctx))
        tls_die("klucz prywatny nie pasuje do certyfikatu");

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
static int serve_client(SSL *ssl, const char *peer)
{
    // handshake TLS: ClientHello → ServerHello, certyfikat, ... → Finished
    int ret = SSL_accept(ssl);
    if (ret <= 0) {
        fprintf(stderr, "%s handshake z %s nieudany\n", TAG, peer);
        tls_report_error(ssl, ret, TAG);
        return 0;   /* sesji TLS nie było, więc nie ma czego zamykać przez SSL_shutdown */
    }
    tls_print_session(ssl, TAG);

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

static void handle_client(SSL_CTX *ctx, int cfd, const char *peer)
{
    set_socket_timeouts(cfd, IO_TIMEOUT_SEC);

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "%s SSL_new nie powiodło się\n", TAG);
        return;
    }
    // OpenSSL dostaje nasze gotowe gniazdo TCP – TLS działa nad naszą warstwą 4
    SSL_set_fd(ssl, cfd);

    if (serve_client(ssl, peer)) {
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

    check_key_permissions(key);
    SSL_CTX *ctx = create_context(cert, key, tls13_only);

    int lfd = create_listen_socket(family, port);

    struct sockaddr_storage local;
    socklen_t local_len = sizeof local;
    char addr[ADDR_STR_LEN];
    if (getsockname(lfd, (struct sockaddr *)&local, &local_len) < 0)
        die("getsockname");
    printf("%s nasłuchuję na %s (min. %s, Ctrl+C kończy)\n", TAG,
           addr_to_str((struct sockaddr *)&local, local_len, addr, sizeof addr),
           tls13_only ? "TLS 1.3" : "TLS 1.2");

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

        handle_client(ctx, cfd, addr);
        close(cfd);
        printf("%s koniec sesji z %s\n", TAG, addr);
    }

    printf("\n%s zamykam serwer\n", TAG);
    close(lfd);
    SSL_CTX_free(ctx);
    return 0;
}
