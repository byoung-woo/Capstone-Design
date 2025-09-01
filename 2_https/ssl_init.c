/*
 * ssl_init.c ― OpenSSL 초기화 + 컨텍스트 생성 (ECDHE-only)
 *
 *  변경 사항
 *  1) configure_server_context() 내부에
 *     - SSL_CTX_set_cipher_list()      → TLS1.2 이하 ECDHE 전용
 *     - SSL_CTX_set_ciphersuites()     → TLS1.3 선호 리스트 명시
 *     - SSL_CTX_set1_groups_list()     → 허용 곡선(P-256, P-384, X25519) 제한
 *
 *  결과: 모든 세션 대칭키가 ECDHE(PFS)로 교환됨
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "ssl_init.h"

/* -------------- 라이브러리 전역 초기화 / 종료 -------------- */
void init_openssl(void)
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl(void)
{
    EVP_cleanup();
}

/* -------------- 서버용 컨텍스트 생성 -------------- */
SSL_CTX *create_server_context(void)
{
    const SSL_METHOD *method = TLS_server_method();       /* TLS 1.2~1.3 */
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* TLS 1.2 이상 강제 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    return ctx;
}

/* -------------- 인증서 / 개인키 로딩 + ECDHE 전용 설정 -------------- */
void configure_server_context(SSL_CTX *ctx,
                              const char *cert_file,
                              const char *key_file)
{
    /* (1) 인증서·개인키 로딩 */
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx,  key_file,  SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* (2) TLS 1.2 이하: ECDHE-계열 Cipher Suite만 허용 */
    /*    - AES-GCM, CHACHA20-POLY1305 우선
     *    - aNULL/eNULL/MD5/RC4 등 위험 수트는 제거
     */
    if (!SSL_CTX_set_cipher_list(ctx,
        "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!RC4"))
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* (3) TLS 1.3: 기본적으로 PFS지만, 선호 순서를 명시 */
#if defined(TLS1_3_VERSION)
    if (!SSL_CTX_set_ciphersuites(ctx,
        "TLS_AES_256_GCM_SHA384:"
        "TLS_AES_128_GCM_SHA256:"
        "TLS_CHACHA20_POLY1305_SHA256"))
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
#endif/* (4) 허용 곡선(EC 그룹) 제한: P-256, P-384, X25519 */
#if OPENSSL_VERSION_NUMBER >= 0x10101000L   /* ≥ 1.1.1 */
    if (!SSL_CTX_set1_groups_list(ctx, "P-256:P-384:X25519")) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
#else       /* 1.1.0 이하: 자동으로 ECDH 선택 */
    SSL_CTX_set_ecdh_auto(ctx, 1);
#endif
}

