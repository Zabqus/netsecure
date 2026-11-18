/*
 * net_common.h – wspólne funkcje pomocnicze dla wszystkich programów (z projektu 1).
 * Implementacja w net_common.c (biblioteka statyczna "netcommon").
 */
#ifndef NET_COMMON_H
#define NET_COMMON_H

#include <stddef.h>      /* size_t */
#include <sys/socket.h>  /* struct sockaddr, socklen_t */

// Bufor na tekst "host:port" / "[host]:port" – najdłuższy adres IPv6 ma 45 znaków.
#define ADDR_STR_LEN 64

// Wypisuje błąd (perror) i kończy program.
_Noreturn void die(const char *msg);

// Adres gniazda jako tekst: "192.168.1.202:43122" albo "[fd00:10::202]:43122".
const char *addr_to_str(const struct sockaddr *sa, socklen_t len, char *buf, size_t n);

// "-4" → AF_INET, "-6" → AF_INET6, inne → -1.
int parse_family(const char *flag);

// Długość tekstu bez końcowych '\n' / '\r' – do ładnego logowania.
size_t text_len(const char *buf, size_t n);

// 1, jeśli napis jest adresem IPv4 lub IPv6 (a nie nazwą hosta).
int is_ip_address(const char *s);

#endif /* NET_COMMON_H */
