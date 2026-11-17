# CMakeLists.txt – budowanie projektu netsecure (C11 + OpenSSL 3.5).
# Budowanie: bash scripts/build.sh   (binarki trafiają do ./build)

# 3.25 – Debian 13 ma CMake 3.31, więc działa bez doinstalowywania nowszej wersji
cmake_minimum_required(VERSION 3.25)
project(netsecure C)

# --- Standard języka ---------------------------------------------------------
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)        # czyste -std=c11, bez rozszerzeń GNU

# W trybie -std=c11 nagłówki systemowe ukrywają funkcje POSIX (getaddrinfo, sigaction...).
# _DEFAULT_SOURCE z powrotem je włącza (tak samo jak w projekcie 1).
add_compile_definitions(_DEFAULT_SOURCE)

# --- Tryb budowania ----------------------------------------------------------
# Domyślnie RelWithDebInfo = -O2 -g: optymalizacja (potrzebna dla _FORTIFY_SOURCE)
# i symbole debugowe (czytelne ślady w gdb/valgrind).
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

# --- Ostrzeżenia i utwardzenie kompilacji ------------------------------------
add_compile_options(
    -Wall -Wextra -pedantic   # ostrzeżenia o typowych błędach i niezgodności ze standardem
    -Wformat=2                # dokładne sprawdzanie printf/scanf: zły typ argumentu,
                              # format niebędący stałym napisem
    -Wformat-security         # chroni przed: format string (printf(dane_od_peera));
                              # zawiera się w -Wformat=2, zostawiamy jawnie dla czytelności
    -fstack-protector-strong  # chroni przed: przepełnieniem bufora na stosie – kanarek
                              # między buforem a adresem powrotu, nadpisanie = abort()
)

# _FORTIFY_SOURCE=2: glibc podmienia memcpy/strcpy/snprintf... na wersje sprawdzające
# rozmiar bufora (gdy kompilator go zna) – chroni przed przepełnieniem bufora.
# Działa tylko z optymalizacją (-O1+), dlatego pomijamy go w trybie Debug (-O0).
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(_FORTIFY_SOURCE=2)
endif()

# --- OpenSSL -----------------------------------------------------------------
# Wymagamy co najmniej 3.5 (wersja z wykładu, API serwera QUIC). Pakiet: libssl-dev.
find_package(OpenSSL 3.5 REQUIRED)
message(STATUS "OpenSSL: ${OPENSSL_VERSION} (${OPENSSL_INCLUDE_DIR})")

# --- Biblioteka wspólna ------------------------------------------------------
add_library(netcommon STATIC
    common/net_common.c
    common/tls_common.c
)
target_include_directories(netcommon PUBLIC common)
# libssl (TLS/QUIC) i libcrypto (klucze, certyfikaty X.509, błędy ERR_*)
target_link_libraries(netcommon PUBLIC OpenSSL::SSL OpenSSL::Crypto)

# --- Programy ----------------------------------------------------------------
add_executable(tls_server tls/tls_server.c)
target_link_libraries(tls_server PRIVATE netcommon)

add_executable(tls_client tls/tls_client.c)
target_link_libraries(tls_client PRIVATE netcommon)

# quic_client (etap 6) i quic_server (etap 7) dojdą tutaj później.
