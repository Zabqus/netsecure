/*
 * quic_server.c – serwer echo QUIC (ocena 5.0).
 *
 * Uruchomienie:
 *   ./build/quic_server --cert pki/out/server/server.crt --key pki/out/server/server.key
 *   ./build/quic_server -6 -p 4433 --cert ... --key ...
 *
 * Przebieg:
 *   SSL_CTX (OSSL_QUIC_server_method, certyfikat + klucz, wybór ALPN) → socket(UDP)/bind →
 *   gniazdo w tryb nieblokujący (wymóg QUIC) → SSL_new_listener + SSL_set_fd → SSL_listen →
 *   pętla: SSL_accept_connection → SSL_do_handshake → SSL_read_ex/SSL_write_ex na domyślnym
 *   strumieniu (echo) aż do FIN klienta → SSL_stream_conclude (nasz FIN) → SSL_shutdown → SSL_free
 *
 * Połączenia obsługiwane są po kolei (jedno naraz), jak w serwerze TLS.
 */
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "net_common.h"
#include "tls_common.h"

#define DEFAULT_PORT "4433"
#define MAX_PENDING  8   /* jak BACKLOG w TLS: ile połączeń może czekać na obsłużenie */

#define TAG "[QUIC][srv]"

static void usage(const char *prog)
{
    fprintf(stderr, "Użycie: %s [-4|-6] [-p <port>] --cert <plik> --key <plik>\n"
                    "  -4 / -6        IPv4 (domyślnie) / IPv6\n"
                    "  -p <port>      port UDP (domyślnie " DEFAULT_PORT ")\n"
                    "  --cert <plik>  certyfikat serwera (PEM)\n"
                    "  --key <plik>   klucz prywatny serwera (PEM)\n"
                    "  --version      wersja OpenSSL\n", prog);
    exit(EXIT_FAILURE);
}

// Callback wyboru ALPN – wywoływany w handshake'u z listą protokołów klienta (in).
// Akceptujemy tylko "ns-echo"; inaczej handshake kończy się alertem no_application_protocol.
static int select_alpn(SSL *ssl, const unsigned char **out, unsigned char *out_len,
                       const unsigned char *in, unsigned int in_len, void *arg)
{
    (void)ssl;
    (void)arg;
    unsigned char *sel;
    if (SSL_select_next_proto(&sel, out_len, (const unsigned char *)QUIC_ALPN, QUIC_ALPN_LEN,
                              in, in_len) == OPENSSL_NPN_NEGOTIATED) {
        *out = sel;
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static SSL_CTX *create_context(const char *cert, const char *key)
{
    // QUIC: zawsze TLS 1.3 – minimalnej wersji nie trzeba ustawiać
    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (ctx == NULL)
        tls_die("SSL_CTX_new");

    tls_load_cert_and_key(ctx, cert, key);

    // chroni przed: klientem mówiącym innym protokołem aplikacji niż nasz
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);
    return ctx;
}

// Gniazdo UDP związane z portem – jak w TLS, tylko SOCK_DGRAM i bez listen().
static int create_udp_socket(int family, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *res;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
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
    if (res->ai_family == AF_INET6) {
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on) < 0)
            die("setsockopt(IPV6_V6ONLY)");
    }

    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0)
        die("bind");
    freeaddrinfo(res);

    // QUIC w OpenSSL wymaga nieblokującego gniazda (sam pilnuje retransmisji i timerów);
    // nasze wywołania SSL_* nadal są blokujące
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        die("fcntl(O_NONBLOCK)");
    return fd;
}

// Handshake i echo z jednym klientem. Zwraca 1, gdy wolno zakończyć połączenie
// poprawnie (SSL_stream_conclude + SSL_shutdown), 0 gdy połączenie już nie istnieje.
static int serve_client(SSL *conn)
{
    // SSL_accept_connection mogło oddać połączenie przed końcem handshake'u – dokańczamy
    int ret = SSL_do_handshake(conn);
    if (ret <= 0) {
        fprintf(stderr, "%s handshake nieudany\n", TAG);
        quic_report_error(conn, ret, TAG);
        return 0;
    }
    tls_print_session(conn, TAG);

    char buf[MAX_MSG];
    for (;;) {
        // dane z domyślnego strumienia klienta; odczyt ograniczony rozmiarem bufora
        size_t n;
        if (!SSL_read_ex(conn, buf, sizeof buf, &n))
            return quic_report_error(conn, 0, TAG);

        printf("%s %zu B: \"", TAG, n);
        print_safe(buf, text_len(buf, n));
        printf("\"\n");

        size_t written;
        if (!SSL_write_ex(conn, buf, n, &written))
            return quic_report_error(conn, 0, TAG);
    }
}

int main(int argc, char *argv[])
{
    int family = AF_INET;
    const char *port = DEFAULT_PORT;
    const char *cert = NULL;
    const char *key = NULL;

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
        else if (strcmp(argv[i], "--version") == 0) {
            tls_print_version("quic_server");
            return 0;
        } else
            usage(argv[0]);
    }
    if (cert == NULL || key == NULL)
        usage(argv[0]);

    setvbuf(stdout, NULL, _IOLBF, 0);

    // SIGINT (Ctrl+C) zostaje z domyślną akcją – zakończenie procesu. Inaczej niż w TLS:
    // blokujące czekanie wewnątrz OpenSSL QUIC po sygnale wznawia się samo, więc flaga
    // ustawiona w handlerze nigdy nie zostałaby sprawdzona. Gniazdo i pamięć zwolni system.

    check_key_permissions(key, TAG);
    SSL_CTX *ctx = create_context(cert, key);

    int fd = create_udp_socket(family, port);

    // listener – obiekt przyjmujący nowe połączenia QUIC na jednym gnieździe UDP
    // (odpowiednik gniazda nasłuchującego w TCP)
    SSL *listener = SSL_new_listener(ctx, 0);
    if (listener == NULL)
        tls_die("SSL_new_listener");
    if (!SSL_set_fd(listener, fd))
        tls_die("SSL_set_fd");

    // chroni przed: zalaniem serwera nowymi połączeniami – nadmiarowe pakiety Initial
    // są odrzucane, gdy w kolejce czeka już MAX_PENDING połączeń
    if (!SSL_set_generic_value_uint(listener, SSL_VALUE_QUIC_MAX_PENDING_CONNS, MAX_PENDING))
        tls_die("SSL_VALUE_QUIC_MAX_PENDING_CONNS");

    // Domyślnie włączone i celowo zostawione (bez SSL_LISTENER_FLAG_NO_VALIDATE):
    // walidacja adresu klienta (pakiet Retry) – chroni przed: atakiem ze sfałszowanym adresem
    // źródłowym (wzmocnienie odpowiedzi, zalewanie połączeniami jak SYN flood w TCP).
    // Idle timeout 30 s (domyślny OpenSSL; obowiązuje mniejszy z obu stron) – chroni przed:
    // klientem, który połączy się i nic nie wysyła.
    if (!SSL_listen(listener))
        tls_die("SSL_listen");

    struct sockaddr_storage local;
    socklen_t local_len = sizeof local;
    char addr[ADDR_STR_LEN];
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) < 0)
        die("getsockname");
    printf("%s nasłuchuję na %s/udp, ALPN ns-echo (Ctrl+C kończy)\n", TAG,
           addr_to_str((struct sockaddr *)&local, local_len, addr, sizeof addr));

    int count = 0;
    for (;;) {
        ERR_clear_error();   /* czysta kolejka błędów dla każdego połączenia */

        // czeka (blokująco) na nowe połączenie od klienta
        SSL *conn = SSL_accept_connection(listener, 0);
        if (conn == NULL) {
            fprintf(stderr, "%s SSL_accept_connection nie powiodło się\n", TAG);
            ERR_print_errors_fp(stderr);
            continue;
        }
        // adresu klienta nie wypisujemy: w QUIC połączenie identyfikuje Connection ID,
        // a nie para adres:port (adres klienta może się zmienić – migracja połączenia)
        printf("%s nowe połączenie QUIC #%d\n", TAG, ++count);

        if (serve_client(conn)) {
            // nasz FIN na strumieniu, potem CONNECTION_CLOSE; SSL_shutdown czeka,
            // aż klient potwierdzi odebranie wszystkich danych
            SSL_stream_conclude(conn, 0);
            int ret;
            while ((ret = SSL_shutdown(conn)) == 0)
                ;
            if (ret < 0)
                quic_report_error(conn, ret, TAG);
        }
        SSL_free(conn);
        printf("%s koniec połączenia #%d\n", TAG, count);
    }
}
