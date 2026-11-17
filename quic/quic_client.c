/*
 * quic_client.c – klient echo QUIC (ocena 4.5).
 *
 * Uruchomienie:
 *   ./build/quic_client -h 192.168.1.201 --ca pki/out/ca/ca.crt
 *   ./build/quic_client -6 -h fd00:10::201 --ca pki/out/ca/ca.crt -m "ala ma kota"
 *   ./build/quic_client -h net-server -p 4433 --ca pki/out/ca/ca.crt
 *
 * Przebieg:
 *   SSL_CTX (OSSL_QUIC_client_method, zaufane CA) → getaddrinfo/socket(UDP)/connect →
 *   gniazdo w tryb nieblokujący (wymóg QUIC) → SSL_new + SSL_set_fd → nazwa/IP serwera, ALPN,
 *   adres serwera, idle timeout → SSL_connect (handshake QUIC = TLS 1.3) →
 *   SSL_write_ex/SSL_read_ex na domyślnym strumieniu (echo) → SSL_stream_conclude (FIN) →
 *   SSL_shutdown (CONNECTION_CLOSE) → SSL_free → close
 *
 * QUIC zawsze używa TLS 1.3 i zawsze weryfikuje certyfikat – nie ma trybu --insecure.
 */
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#include "net_common.h"
#include "tls_common.h"

#define DEFAULT_PORT "4433"

#define TAG "[QUIC][cli]"

static void usage(const char *prog)
{
    fprintf(stderr, "Użycie: %s [-4|-6] -h <host> [-p <port>] --ca <plik> [--name <nazwa>] [-m \"wiadomość\"]\n"
                    "  -h <host>      adres lub nazwa serwera\n"
                    "  -p <port>      port UDP serwera (domyślnie " DEFAULT_PORT ")\n"
                    "  --ca <plik>    zaufany certyfikat CA (wymagany)\n"
                    "  --name <nazwa> nazwa/IP oczekiwane w certyfikacie (domyślnie -h)\n"
                    "  -m <tekst>     wyślij jedną wiadomość i zakończ\n"
                    "  --version      wersja OpenSSL\n", prog);
    exit(EXIT_FAILURE);
}

static SSL_CTX *create_context(const char *ca_file)
{
    // QUIC: wersja TLS jest zawsze 1.3 – minimalnej wersji nie trzeba ustawiać
    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (ctx == NULL)
        tls_die("SSL_CTX_new");

    // chroni przed: podszyciem się pod serwer – handshake przerwany, jeśli certyfikat
    // nie jest podpisany przez zaufane CA
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (!SSL_CTX_load_verify_file(ctx, ca_file))
        tls_die("nie udało się wczytać pliku --ca");
    return ctx;
}

// Tworzy gniazdo UDP "połączone" z serwerem. connect() dla UDP niczego nie wysyła –
// tylko zapamiętuje adres docelowy. Adres serwera trafia też do *peer (dla OpenSSL).
static int connect_udp(int family, const char *host, const char *port,
                       struct sockaddr_storage *peer)
{
    struct addrinfo hints;
    struct addrinfo *res;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICSERV;

    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo(%s): %s\n", host, gai_strerror(rc));
        exit(EXIT_FAILURE);
    }

    int fd = -1;
    char addr[ADDR_STR_LEN];
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            perror("socket");
            continue;
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            memcpy(peer, ai->ai_addr, ai->ai_addrlen);
            printf("%s gniazdo UDP → %s\n", TAG,
                   addr_to_str(ai->ai_addr, ai->ai_addrlen, addr, sizeof addr));
            break;
        }
        perror("connect");
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        fprintf(stderr, "%s nie udało się utworzyć gniazda do %s:%s\n", TAG, host, port);
        exit(EXIT_FAILURE);
    }

    // QUIC w OpenSSL wymaga nieblokującego gniazda: sam pilnuje czasu (retransmisje,
    // timeouty), więc nie może utknąć w recv(). Nasze wywołania SSL_* nadal są blokujące
    // (SSL_set_blocking_mode – domyślnie włączony).
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        die("fcntl(O_NONBLOCK)");
    return fd;
}

// Adres serwera w postaci BIO_ADDR – tego wymaga SSL_set1_initial_peer_addr.
static BIO_ADDR *make_bio_addr(const struct sockaddr_storage *ss)
{
    BIO_ADDR *a = BIO_ADDR_new();
    if (a == NULL)
        return NULL;

    int ok;
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)ss;
        ok = BIO_ADDR_rawmake(a, AF_INET, &s4->sin_addr, sizeof s4->sin_addr, s4->sin_port);
    } else {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ss;
        ok = BIO_ADDR_rawmake(a, AF_INET6, &s6->sin6_addr, sizeof s6->sin6_addr, s6->sin6_port);
    }
    if (!ok) {
        BIO_ADDR_free(a);
        return NULL;
    }
    return a;
}

// Odbiera dokładnie len bajtów – odpowiedź może przyjść w kilku pakietach QUIC.
static int read_exact(SSL *ssl, char *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        size_t n;
        if (!SSL_read_ex(ssl, buf + got, len - got, &n)) {
            quic_report_error(ssl, 0, TAG);
            return -1;
        }
        got += n;
    }
    return 0;
}

// Wysyła tekst i wypisuje echo. 0 – OK, -1 – koniec.
static int echo_once(SSL *ssl, const char *text, size_t len)
{
    char reply[MAX_MSG];
    size_t written;

    // w trybie blokującym SSL_write_ex wysyła wszystko albo zwraca błąd
    if (!SSL_write_ex(ssl, text, len, &written)) {
        quic_report_error(ssl, 0, TAG);
        return -1;
    }
    if (read_exact(ssl, reply, len) < 0)
        return -1;

    printf("%s odpowiedź (%zu B): \"", TAG, len);
    print_safe(reply, text_len(reply, len));
    printf("\"\n");
    return 0;
}

static void cleanup(SSL *ssl, int fd, SSL_CTX *ctx, BIO_ADDR *peer)
{
    // w odwrotnej kolejności niż tworzenie
    SSL_free(ssl);
    BIO_ADDR_free(peer);
    close(fd);
    SSL_CTX_free(ctx);
}

int main(int argc, char *argv[])
{
    const char *host = NULL;
    const char *port = DEFAULT_PORT;
    const char *ca_file = NULL;
    const char *name = NULL;
    const char *message = NULL;
    int family = AF_UNSPEC;

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
        else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc)
            name = argv[++i];
        else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc)
            message = argv[++i];
        else if (strcmp(argv[i], "--version") == 0) {
            tls_print_version("quic_client");
            return 0;
        } else
            usage(argv[0]);
    }
    // weryfikacja certyfikatu jest w QUIC obowiązkowa – bez --ca nie łączymy się
    if (host == NULL || ca_file == NULL)
        usage(argv[0]);
    if (name == NULL)
        name = host;

    setvbuf(stdout, NULL, _IOLBF, 0);

    SSL_CTX *ctx = create_context(ca_file);

    struct sockaddr_storage peer_ss;
    int fd = connect_udp(family, host, port, &peer_ss);

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
        tls_die("SSL_new");
    // dla obiektu QUIC SSL_set_fd tworzy BIO datagramowe (UDP) na naszym gnieździe
    if (!SSL_set_fd(ssl, fd))
        tls_die("SSL_set_fd");

    // chroni przed: serwerem z ważnym certyfikatem wystawionym na INNĄ nazwę/adres
    if (!SSL_set1_host(ssl, name))
        tls_die("SSL_set1_host");
    // SNI tylko dla nazwy, nie dla adresu IP
    if (!is_ip_address(name) && !SSL_set_tlsext_host_name(ssl, name))
        tls_die("SSL_set_tlsext_host_name");

    // ALPN – w QUIC obowiązkowy: serwer musi wiedzieć, jaki protokół aplikacji mówimy.
    // Uwaga: SSL_set_alpn_protos zwraca 0 przy SUKCESIE.
    if (SSL_set_alpn_protos(ssl, (const unsigned char *)QUIC_ALPN, QUIC_ALPN_LEN) != 0)
        tls_die("SSL_set_alpn_protos");

    // UDP nie ma połączenia – OpenSSL musi znać adres, na który wysłać pierwszy pakiet
    BIO_ADDR *peer = make_bio_addr(&peer_ss);
    if (peer == NULL || !SSL_set1_initial_peer_addr(ssl, peer))
        tls_die("SSL_set1_initial_peer_addr");

    // chroni przed: zawieszeniem klienta, gdy serwer przestanie odpowiadać – połączenie
    // bez żadnych pakietów przez IO_TIMEOUT_SEC jest zamykane (ustawiane przed handshake)
    if (!SSL_set_feature_request_uint(ssl, SSL_VALUE_QUIC_IDLE_TIMEOUT, IO_TIMEOUT_SEC * 1000))
        tls_die("SSL_VALUE_QUIC_IDLE_TIMEOUT");

    // handshake QUIC: pakiety Initial/Handshake niosą wiadomości TLS 1.3 (ClientHello, ...)
    int ret = SSL_connect(ssl);
    if (ret <= 0) {
        fprintf(stderr, "%s handshake nieudany\n", TAG);
        long v = SSL_get_verify_result(ssl);
        if (v != X509_V_OK)
            fprintf(stderr, "%s weryfikacja certyfikatu: %s\n", TAG, X509_verify_cert_error_string(v));
        quic_report_error(ssl, ret, TAG);
        cleanup(ssl, fd, ctx, peer);
        return EXIT_FAILURE;
    }

    tls_print_session(ssl, TAG);
    tls_print_peer_cert(ssl, TAG);

    // Dane idą domyślnym strumieniem: pierwszy SSL_write_ex otwiera dwukierunkowy strumień
    // klienta, a SSL_read_ex/SSL_write_ex na obiekcie połączenia działają na nim.
    char line[MAX_MSG];
    int ok = 1;
    if (message != NULL) {
        int len = snprintf(line, sizeof line, "%s\n", message);
        if (len >= (int)sizeof line)
            len = (int)sizeof line - 1;   /* za długa – obcinamy do limitu */
        ok = echo_once(ssl, line, (size_t)len) == 0;
    } else {
        printf("%s wpisuj linie, Ctrl+D kończy\n", TAG);
        while (fgets(line, sizeof line, stdin) != NULL) {
            if (echo_once(ssl, line, strlen(line)) != 0) {
                ok = 0;
                break;
            }
        }
    }

    if (ok) {
        // FIN na strumieniu: "nie wyślę więcej danych" – serwer odpowie swoim FIN
        if (SSL_stream_conclude(ssl, 0)) {
            char tmp[16];
            size_t n;
            if (!SSL_read_ex(ssl, tmp, sizeof tmp, &n))
                ok = quic_report_error(ssl, 0, TAG);
        }
    }
    if (ok) {
        // CONNECTION_CLOSE – czeka aż serwer potwierdzi odbiór wszystkich naszych danych
        while ((ret = SSL_shutdown(ssl)) == 0)
            ;
        if (ret < 0)
            quic_report_error(ssl, ret, TAG);
    }

    cleanup(ssl, fd, ctx, peer);
    return ok ? 0 : EXIT_FAILURE;
}
