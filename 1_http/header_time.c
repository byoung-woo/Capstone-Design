#include "header_time.h"
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

void send_response_with_time(int client_fd) {
    time_t now = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

    char body[256];
    int body_len = snprintf(body, sizeof(body),
        "<html><body><h1>Current time: %s</h1></body></html>", time_str);

    char header[256];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "\r\n", body_len);

    write(client_fd, header, header_len);
    write(client_fd, body, body_len);
}