// ssl_handler.c
// HTTPS 보안 통신을 위한 SSL/TLS 핸들러 모듈.
// SSL/TLS 컨텍스트를 초기화하고, 인증서 및 개인 키를 로드합니다.

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "ssl_handler.h"
#include "logger.h"
#include "webserver.h" // CERT_FILE, KEY_FILE 정의를 위해 추가

// SSL/TLS 컨텍스트는 서버 전체에서 공유됩니다.
static SSL_CTX* ssl_ctx;

// SSL/TLS 컨텍스트를 초기화하고 인증서를 로드하는 함수
void init_ssl() {
    // OpenSSL 라이브러리 초기화
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // SSL/TLS 컨텍스트 생성
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (ssl_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        log_error("Failed to create SSL context.");
        exit(1);
    }

    // 서버 인증서 및 개인 키 로드
    // 인증서 파일 경로는 Makefile에서 정의된 CERT_FILE을 사용합니다.
    if (SSL_CTX_use_certificate_file(ssl_ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        log_error("Failed to load server certificate.");
        exit(1);
    }
    
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        log_error("Failed to load private key.");
        exit(1);
    }
    
    // 개인 키와 인증서가 일치하는지 확인
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        log_error("Private key does not match the certificate.");
        exit(1);
    }

    log_error("SSL/TLS initialized successfully.");
}

// 초기화된 SSL/TLS 컨텍스트를 반환하는 함수
SSL_CTX* get_ssl_context() {
    return ssl_ctx;
}

// SSL/TLS 관련 자원을 정리하는 함수
void cleanup_ssl() {
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
    EVP_cleanup();
}