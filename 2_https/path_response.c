#include "path_response.h"


#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

void handle_request_path(SSL *ssl, const char *request) {
    char method[8], url[256], protocol[16];
    sscanf(request, "%s %s %s", method, url, protocol);

    if (strcmp(url, "/") == 0) {
        const char *body = "<html><body><h1>Hello, User!</h1></body></html>";
        char resp[512];
        int len = snprintf(resp, sizeof(resp),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: text/html; charset=UTF-8\r\n"
             "Content-Length: %zu\r\n\r\n%s",
             strlen(body), body);
        SSL_write(ssl, resp, len);
    } else {
        const char *body = "<html><body><h1>404 - Page Not Found</h1></body></html>";
        char resp[512];
        int len = snprintf(resp, sizeof(resp),
             "HTTP/1.1 404 Not Found\r\n"
             "Content-Type: text/html; charset=UTF-8\r\n"
             "Content-Length: %zu\r\n\r\n%s",
             strlen(body), body);
        SSL_write(ssl, resp, len);
    }
}


