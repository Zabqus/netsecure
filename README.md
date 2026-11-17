# netsecure

Bezpieczna komunikacja klient/serwer w C11 z użyciem OpenSSL 3.5:
TCP + TLS (z własnym CA i wzajemnym uwierzytelnianiem) oraz QUIC.
Kontynuacja projektu 1 (*netstarter*). Gniazda tworzymy sami (`socket`, `bind`, `connect`, `accept`),
a OpenSSL dostaje gotowy deskryptor, czyli TLS/QUIC działa nad naszą warstwą 4.

## Zakres

| Ocena | Zakres | Status |
|---|---|---|
| 3.0 | Klient i serwer TCP + TLS, certyfikat self-signed | – |
| 3.5 | Własne CA, wystawianie certyfikatów | – |
| 4.0 | Mutual TLS (certyfikat klienta) | – |
| 4.5 | Klient QUIC | – |
| 5.0 | Serwer QUIC | – |

## Wymagania

Debian 13 (OpenSSL 3.5), gcc, CMake ≥ 3.25:

```bash
sudo apt install build-essential cmake git libssl-dev libssl-doc
openssl version        # oczekiwane: OpenSSL 3.5.x
```

## Budowanie

```bash
bash scripts/build.sh              # domyślnie RelWithDebInfo (-O2 -g)
./build/tls_server --version
./build/tls_client --version
```

## Struktura

```
common/   net_common.{h,c} – gniazda, adresy (z projektu 1)
          tls_common.{h,c} – wspólne helpery OpenSSL
tls/      tls_server.c, tls_client.c      (3.0 / 3.5 / 4.0)
quic/     quic_server.c, quic_client.c    (4.5 / 5.0)
pki/      konfiguracja CA i certyfikatów (pliki wygenerowane w pki/out/ – poza repo)
scripts/  build.sh, skrypty PKI
docs/     opis etapów, bezpieczeństwo, pytania kontrolne
```

## Środowisko testowe

| Rola | Host | IPv4 | IPv6 |
|---|---|---|---|
| Serwer | `net-server` | 192.168.1.201 | fd00:10::201 |
| Klient | `net-client` | 192.168.1.202 | fd00:10::202 |

Porty: TLS **5443/TCP**, QUIC **4433/UDP**.
