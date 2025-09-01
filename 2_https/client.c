
/* client.c ― HTTPS 테스트 클라이언트
 *
 *  • TLS 1.2 이상으로 서버에 접속
 *  • 간단한 HTTP GET 요청 전송 후 응답 본문을 stdout 으로 출력
 *
 *  컴파일: gcc client.c -o client -lssl -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUF_SIZE 4096

/* -------------------------------------------------------- */
static int connect_tcp(const char *host, int port)
{
    struct sockaddr_in addr;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); exit(EXIT_FAILURE); }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);

    /* 도메인 or IP 문자열 → 네트워크 바이트 순 변환 */
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        /* IP가 아니면 gethostbyname 사용 */
        struct hostent *he = gethostbyname(host);
        if (!he) { herror("gethostbyname"); exit(EXIT_FAILURE); }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect"); exit(EXIT_FAILURE);
    }
    return sock;
}
/* -------------------------------------------------------- */

int main(int argc, char *argv[])
{
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    int         port = (argc > 2) ? atoi(argv[2]) : 8443;
    const char *path = (argc > 3) ? argv[3] : "/";

    /* 1) OpenSSL 초기화 */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { ERR_print_errors_fp(stderr); exit(EXIT_FAILURE); }

    /* TLS 1.2 이상 강제 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    /* 2) TCP 소켓 연결 */
    int sock = connect_tcp(host, port);

    /* 3) SSL 핸드셰이크 */
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl); close(sock); SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    /* 4) HTTP GET 요청 작성 */
    char req[512];
    int  len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: capstone-client/1.0\r\n"
        "Connection: close\r\n\r\n", path, host);

    SSL_write(ssl, req, len);

    /* 5) 응답 출력 */
    char buf[BUF_SIZE];
    int n;
    while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, n, stdout);

    /* 6) 정리 */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}

