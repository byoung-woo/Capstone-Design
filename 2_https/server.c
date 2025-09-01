/* server.c ― HTTPS 버전 (포트 8443) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ssl_init.h"    
#include "logger.h"
#include "path_response.h" 

#define PORT         8443
#define BACKLOG      10
#define BUFFER_SIZE  4096


/* 1. 클라이언트-당 TLS 세션 처리                              */
static void handle_client_tls(SSL *ssl, struct sockaddr_in *caddr)
{
    char buf[BUFFER_SIZE];
    int n = SSL_read(ssl, buf, BUFFER_SIZE - 1);
    if (n <= 0) {
        ERR_print_errors_fp(stderr);
        return;
    }
    buf[n] = '\0';

    /* ── 클라이언트 IP 문자열화 ── */
    char cip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(caddr->sin_addr), cip, sizeof(cip));

    /* ── 요청 로그 ── */
    log_request(cip, buf);

    /* ── URL 분기 처리 ──
     *    NOTE: path_response.c / 기타 핸들러의 write() 호출을
     *          SSL_write()로 교체해야 완전한 TLS 응답이 됨.
     */
    int fd = SSL_get_fd(ssl);  
    handle_request_path(ssl, buf);
}


int main(void)
{
    /* ── 0) OpenSSL 전역 초기화 ── */
    init_openssl();
    SSL_CTX *ctx = create_server_context();
    configure_server_context(ctx, "server.crt", "server.key");

    /* ── 1) TCP 소켓 준비 ── */
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket"); exit(EXIT_FAILURE); }

    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in saddr = {0};
    saddr.sin_family      = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port        = htons(PORT);

    if (bind(sfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("bind"); exit(EXIT_FAILURE);
    }
    if (listen(sfd, BACKLOG) < 0) {
        perror("listen"); exit(EXIT_FAILURE);
    }

    printf("🔒 HTTPS 서버가 포트 %d에서 실행 중...\n", PORT);

    /* ── 2) 메인 accept 루프 ── */
    for (;;)
    {
        struct sockaddr_in caddr; socklen_t clen = sizeof(caddr);
        int cfd = accept(sfd, (struct sockaddr *)&caddr, &clen);
        if (cfd < 0) { perror("accept"); continue; }

        /* ── TLS 세션 생성 & 핸드셰이크 ── */
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, cfd);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(cfd);
            SSL_free(ssl);
            continue;
        }

        /* ── 요청 처리 ── */
        handle_client_tls(ssl, &caddr);

        /* ── 세션 종료 ── */
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(cfd);
    }

    /* ── 3) 종료 정리 ── */
    SSL_CTX_free(ctx);
    cleanup_openssl();
    close(sfd);
    return 0;
}
