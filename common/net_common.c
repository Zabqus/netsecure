/*
 * net_common.c – implementacja wspólnych helperów (opis w net_common.h).
 * Przeniesione z projektu 1 (netstarter); usunięte addr_to_host i inet_checksum
 * (służyły do gniazd surowych, tutaj niepotrzebne).
 */
#include "net_common.h"

#include <errno.h>       /* errno, EINTR */
#include <netdb.h>       /* getnameinfo, gai_strerror, NI_* */
#include <stdio.h>       /* perror, snprintf */
#include <stdlib.h>      /* exit */
#include <string.h>      /* strcmp */
#include <netinet/in.h>  /* AF_INET, AF_INET6 */
#include <arpa/inet.h>   /* inet_pton */

void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

const char *addr_to_str(const struct sockaddr *sa, socklen_t len, char *buf, size_t n)
{
    char host[NI_MAXHOST];
    char port[NI_MAXSERV];

    // zamieniamy adres i port na tekst (liczbowo, bez zapytań DNS) – działa dla IPv4 i IPv6
    int rc = getnameinfo(sa, len, host, sizeof host, port, sizeof port,
                         NI_NUMERICHOST | NI_NUMERICSERV);
    if (rc != 0) {
        snprintf(buf, n, "<nieznany adres: %s>", gai_strerror(rc));
        return buf;
    }

    // IPv6 w nawiasach, bo sam adres zawiera dwukropki
    if (sa->sa_family == AF_INET6)
        snprintf(buf, n, "[%s]:%s", host, port);
    else
        snprintf(buf, n, "%s:%s", host, port);

    return buf;
}

int send_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;   /* pierwszy niewysłany bajt */
    size_t left = len;     /* ile zostało do wysłania */

    while (left > 0) {
        // wysyłamy resztę danych (send() może przyjąć mniej, niż prosiliśmy)
        // MSG_NOSIGNAL: przy zamkniętym połączeniu błąd zamiast zabicia programu
        ssize_t sent = send(fd, p, left, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR)   /* przerwane sygnałem – ponawiamy */
                continue;
            return -1;
        }
        p += sent;
        left -= (size_t)sent;
    }
    return 0;
}

int parse_family(const char *flag)
{
    if (strcmp(flag, "-4") == 0)
        return AF_INET;
    if (strcmp(flag, "-6") == 0)
        return AF_INET6;
    return -1;
}

size_t text_len(const char *buf, size_t n)
{
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        n--;
    return n;
}

int is_ip_address(const char *s)
{
    unsigned char tmp[sizeof(struct in6_addr)];
    return inet_pton(AF_INET, s, tmp) == 1 || inet_pton(AF_INET6, s, tmp) == 1;
}
