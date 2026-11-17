# CMakeLists.txt – netsecure (C11 + OpenSSL 3.5). Budowanie: bash scripts/build.sh

# Debian 13 ma CMake 3.31
cmake_minimum_required(VERSION 3.25)
project(netsecure C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# -std=c11 ukrywa funkcje POSIX (getaddrinfo, sigaction...) – _DEFAULT_SOURCE je przywraca
add_compile_definitions(_DEFAULT_SOURCE)

# domyślnie -O2 -g: optymalizacja jest potrzebna dla _FORTIFY_SOURCE
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

add_compile_options(
    -Wall -Wextra -pedantic
    -Wformat=2                # sprawdza argumenty printf/scanf
    -Wformat-security         # chroni przed: format string, np. printf(dane_od_peera)
    -fstack-protector-strong  # chroni przed: przepełnieniem bufora na stosie (kanarek → abort)
)

# chroni przed: przepełnieniem bufora – glibc sprawdza rozmiar w memcpy/snprintf/...
# działa tylko z optymalizacją, więc nie w trybie Debug (-O0)
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(_FORTIFY_SOURCE=2)
endif()

find_package(OpenSSL 3.5 REQUIRED)
message(STATUS "OpenSSL: ${OPENSSL_VERSION}")

add_library(netcommon STATIC
    common/net_common.c
    common/tls_common.c
)
target_include_directories(netcommon PUBLIC common)
target_link_libraries(netcommon PUBLIC OpenSSL::SSL OpenSSL::Crypto)

add_executable(tls_server tls/tls_server.c)
target_link_libraries(tls_server PRIVATE netcommon)

add_executable(tls_client tls/tls_client.c)
target_link_libraries(tls_client PRIVATE netcommon)

add_executable(quic_client quic/quic_client.c)
target_link_libraries(quic_client PRIVATE netcommon)

add_executable(quic_server quic/quic_server.c)
target_link_libraries(quic_server PRIVATE netcommon)
