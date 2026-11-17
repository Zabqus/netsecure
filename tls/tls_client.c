/*
 * tls_client.c – klient echo TCP + TLS (oceny 3.0 / 3.5 / 4.0).
 *
 * Uruchomienie:
 *   ./build/tls_client -h 192.168.1.201 --ca pki/out/selfsigned/server.crt
 *   ./build/tls_client -h 192.168.1.201 --ca pki/out/ca/ca.crt        (zaufane własne CA)
 *   ./build/tls_client -h net-server --ca ... -m "ala ma kota"
 *   ./build/tls_client -h 192.168.1.201 --ca pki/out/ca/ca.crt
 *       --cert pki/out/student-client/student-client.crt
 *       --key pki/out/student-client/student-client.key           (mTLS)
 *   ./build/tls_client -h 192.168.1.201 --insecure       (BEZ weryfikacji – tylko demo)
 *
 * Przebieg:
 *   SSL_CTX (konfiguracja TLS, zaufane CA, przy mTLS własny cert + klucz) → getaddrinfo/socket/connect →
 *   SSL_new + SSL_set_fd → oczekiwana nazwa/IP serwera → SSL_connect (handshake) →
 *   SSL_write/SSL_read (echo) → SSL_shutdown → SSL_free → close
 */
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#include "net_common.h"
#include "tls_common.h"

#define DEFAULT_PORT "5443"

#define TAG "[TLS][cli]"

static void usage(const char *prog)
{
    fprintf(stderr, "Użycie: %s [-4|-6] -h <host> [-p <port>] (--ca <plik> | --insecure)\n"
                    "          [--cert <plik> --key <plik>] [--name <nazwa>] [--tls13] [-m \"wiadomość\"]\n"
                    "  -h <host>      adres lub nazwa serwera\n"
                    "  -p <port>      port serwera (domyślnie " DEFAULT_PORT ")\n"
                    "  --ca <plik>    zaufany certyfikat (CA albo self-signed serwera)\n"
                    "  --insecure     NIE weryfikuj certyfikatu (podatne na MITM!)\n"
                    "  --cert <plik>  certyfikat klienta (mTLS)\n"
                    "  --key <plik>   klucz prywatny klienta (mTLS)\n"
                    "  --name <nazwa> nazwa/IP oczekiwane w certyfikacie (domyślnie -h)\n"
                    "  --tls13        tylko TLS 1.3\n"
                    "  -m <tekst>     wyślij jedną wiadomość i zakończ\n"
                    "  --version      wersja OpenSSL\n", prog);
    exit(EXIT_FAILURE);
}

static SSL_CTX *create_context(const char *ca_file, int insecure, const char *cert,
                               const char *key, int tls13_only)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL)
        tls_die("SSL_CTX_new");

    tls_ctx_harden(ctx, tls13_only);

    if (insecure) {
        // handshake się uda nawet z fałszywym certyfikatem – każdy pośrodku (MITM)
        // może podstawić swój klucz i czytać ruch. Tylko do demonstracji.
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        fprintf(stderr, "%s UWAGA: --insecure – certyfikat serwera NIE jest weryfikowany, "
                        "połączenie podatne na atak man-in-the-middle!\n", TAG);
    } else {
        // chroni przed: podszyciem się pod serwer – handshake przerwany, jeśli certyfikat
        // nie jest podpisany przez zaufane CA (albo nie jest tym zaufanym self-signed)
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (!SSL_CTX_load_verify_file(ctx, ca_file))
            tls_die("nie udało się wczytać pliku --ca");
    }

    // mTLS: certyfikat, którym klient przedstawi się serwerowi, gdy ten o niego poprosi
    if (cert != NULL) {
        check_key_permissions(key, TAG);
        tls_load_cert_and_key(ctx, cert, key);
    }
    return ctx;
}

// Łączy się z host:port po TCP – jak w projekcie 1.
static int connect_to(int family, const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *res;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;

    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo(%s): %s\n", host, gai_strerror(rc));
        exit(EXIT_FAILURE);
    }

    int fd = -1;
    char addr[ADDR_STR_LEN];
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        addr_to_str(ai->ai_addr, ai->ai_addrlen, addr, sizeof addr);

        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            perror("socket");
            continue;
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            printf("%s połączono (TCP) z %s\n", TAG, addr);
            break;
        }
        fprintf(stderr, "%s %s: ", TAG, addr);
        perror("connect");
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        fprintf(stderr, "%s nie udało się połączyć z %s:%s\n", TAG, host, port);
        exit(EXIT_FAILURE);
    }
    return fd;
}

// Odbiera dokładnie len bajtów – odpowiedź może przyjść w kilku rekordach TLS.
// 0 – OK, -1 – koniec/błąd (komunikat już wypisany).
static int read_exact(SSL *ssl, char *buf, int len)
{
    int got = 0;
    while (got < len) {
        int n = SSL_read(ssl, buf + got, len - got);
        if (n <= 0) {
            tls_report_error(ssl, n, TAG);
            return -1;
        }
        got += n;
    }
    return 0;
}

// Wysyła tekst i wypisuje echo. 0 – OK, -1 – koniec.
static int echo_once(SSL *ssl, const char *text, int len)
{
    char reply[MAX_MSG];

    int ret = SSL_write(ssl, text, len);
    if (ret <= 0) {
        tls_report_error(ssl, ret, TAG);
        return -1;
    }
    if (read_exact(ssl, reply, len) < 0)
        return -1;

    printf("%s odpowiedź (%d B): \"", TAG, len);
    print_safe(reply, text_len(reply, (size_t)len));
    printf("\"\n");
    return 0;
}

static void cleanup(SSL *ssl, int fd, SSL_CTX *ctx)
{
    // w odwrotnej kolejności niż tworzenie
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
}

int main(int argc, char *argv[])
{
    const char *host = NULL;
    const char *port = DEFAULT_PORT;
    const char *ca_file = NULL;
    const char *name = NULL;
    const char *cert = NULL;
    const char *key = NULL;
    const char *message = NULL;
    int family = AF_UNSPEC;
    int insecure = 0;
    int tls13_only = 0;

    for (int i = 1; i < argc; i++) {
        int f = parse_family(argv[i]);
        if (f != -1)
            family = f;
        else if (strcmp(argv[i], "-h") == 0 && i + 1 < argc)
            host = argv[++i];
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
            port = argv[++i];
        else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc)
            ca_file = argv[++i];
        else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc)
            cert = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
            key = argv[++i];
        else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc)
            name = argv[++i];
        else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc)
            message = argv[++i];
        else if (strcmp(argv[i], "--insecure") == 0)
            insecure = 1;
        else if (strcmp(argv[i], "--tls13") == 0)
            tls13_only = 1;
        else if (strcmp(argv[i], "--version") == 0) {
            tls_print_version("tls_client");
            return 0;
        } else
            usage(argv[0]);
    }
    if (host == NULL)
        usage(argv[0]);

    // bezpieczny wybór domyślny: bez jawnej decyzji o zaufaniu nie łączymy się wcale
    if (ca_file == NULL && !insecure) {
        fprintf(stderr, "%s podaj --ca <plik> (zalecane) albo --insecure\n", TAG);
        return EXIT_FAILURE;
    }
    if (ca_file != NULL && insecure) {
        fprintf(stderr, "%s --ca i --insecure wykluczają się\n", TAG);
        return EXIT_FAILURE;
    }
    if ((cert == NULL) != (key == NULL)) {
        fprintf(stderr, "%s --cert i --key podaje się razem\n", TAG);
        return EXIT_FAILURE;
    }
    if (name == NULL)
        name = host;

    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);   /* chroni przed: zabiciem procesu przy zapisie do zamkniętego połączenia */

    SSL_CTX *ctx = create_context(ca_file, insecure, cert, key, tls13_only);

    int fd = connect_to(family, host, port);
    set_socket_timeouts(fd, IO_TIMEOUT_SEC);

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
        tls_die("SSL_new");
    SSL_set_fd(ssl, fd);

    // chroni przed: serwerem z ważnym certyfikatem wystawionym na INNĄ nazwę/adres –
    // OpenSSL porówna name z subjectAltName certyfikatu (w 3.x działa też dla IPv4/IPv6)
    if (!SSL_set1_host(ssl, name))
        tls_die("SSL_set1_host");

    // SNI – mówimy serwerowi, z jaką nazwą chcemy rozmawiać; dla adresu IP nie wolno go wysyłać
    if (!is_ip_address(name) && !SSL_set_tlsext_host_name(ssl, name))
        tls_die("SSL_set_tlsext_host_name");

    int ret = SSL_connect(ssl);
    if (ret <= 0) {
        fprintf(stderr, "%s handshake nieudany\n", TAG);
        long v = SSL_get_verify_result(ssl);
        if (v != X509_V_OK)
            fprintf(stderr, "%s weryfikacja certyfikatu: %s\n", TAG, X509_verify_cert_error_string(v));
        tls_report_error(ssl, ret, TAG);
        cleanup(ssl, fd, ctx);
        return EXIT_FAILURE;
    }

    tls_print_session(ssl, TAG);
    tls_print_peer_cert(ssl, TAG);
    if (insecure)
        printf("%s (wynik weryfikacji zignorowany – tryb --insecure)\n", TAG);

    char line[MAX_MSG];
    int ok = 1;
    if (message != NULL) {
        int len = snprintf(line, sizeof line, "%s\n", message);
        if (len >= (int)sizeof line)
            len = (int)sizeof line - 1;   /* za długa – obcinamy do limitu */
        ok = echo_once(ssl, line, len) == 0;
    } else {
        printf("%s wpisuj linie, Ctrl+D kończy\n", TAG);
        // fgets czyta najwyżej sizeof line - 1 znaków – nigdy nie wyjdzie poza bufor
        while (fgets(line, sizeof line, stdin) != NULL) {
            if (echo_once(ssl, line, (int)strlen(line)) != 0) {
                ok = 0;
                break;
            }
        }
    }

    if (ok) {
        // wysyłamy close_notify (SSL_shutdown zwraca 0) i czekamy na close_notify serwera –
        // dzięki temu obie strony wiedzą, że żadne dane nie zostały obcięte
        if (SSL_shutdown(ssl) == 0) {
            char tmp[16];
            ret = SSL_read(ssl, tmp, sizeof tmp);
            if (ret <= 0)
                tls_report_error(ssl, ret, TAG);
        }
    }

    cleanup(ssl, fd, ctx);
    return ok ? 0 : EXIT_FAILURE;
}
