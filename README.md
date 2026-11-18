# netsecure

Bezpieczna komunikacja klient/serwer w C11 z użyciem OpenSSL 3.5:
TCP + TLS (z własnym CA i wzajemnym uwierzytelnianiem) oraz QUIC.
Kontynuacja projektu 1 (*netstarter*). Gniazda tworzymy sami (`socket`, `bind`, `connect`, `accept`),
a OpenSSL dostaje gotowy deskryptor, czyli TLS/QUIC działa nad naszą warstwą 4.

## Zakres

| Ocena | Zakres | Status |
|---|---|---|
| 3.0 | Klient i serwer TCP + TLS, certyfikat self-signed | ✓ |
| 3.5 | Własne CA, wystawianie certyfikatów | ✓ |
| 4.0 | Mutual TLS (certyfikat klienta) | ✓ |
| 4.5 | Klient QUIC | ✓ |
| 5.0 | Serwer QUIC | ✓ |

## Wymagania

Debian 13 (OpenSSL 3.5), gcc, CMake ≥ 3.25:

```bash
sudo apt install build-essential cmake git libssl-dev libssl-doc
openssl version        
```

## Budowanie

```bash
bash scripts/build.sh              
./build/tls_server --version
./build/tls_client --version
./build/quic_server --version
```

## Certyfikaty

```bash
bash scripts/pki_selfsigned.sh             # 3.0: self-signed serwera
bash scripts/pki_ca_init.sh                # 3.5: CA (klucz CA zostaje na net-server)
bash scripts/pki_issue.sh server           # certyfikat serwera od CA
bash scripts/pki_issue.sh client student-client   # 4.0: certyfikat klienta
bash scripts/pki_issue.sh rogue            # obce CA do testów negatywnych
bash scripts/pki_show.sh <cert> [ca.crt]   # podgląd i weryfikacja
```

## Uruchomienie

```bash

./build/tls_server --cert pki/out/server/server.crt --key pki/out/server/server.key \
                   [--ca pki/out/ca/ca.crt --require-client-cert] [-6] [--tls13]
./build/tls_client -h 192.168.1.201 --ca pki/out/ca/ca.crt [-m "tekst"] \
                   [--cert pki/out/student-client/student-client.crt --key pki/out/student-client/student-client.key]

# QUIC
./build/quic_server --cert pki/out/server/server.crt --key pki/out/server/server.key [-6]
./build/quic_client -h 192.168.1.201 --ca pki/out/ca/ca.crt [-m "tekst"]
```




Porty: TLS **5443/TCP**, QUIC **4433/UDP**.
