
#include "fixed_response.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>

void send_fixed_response(int client_fd) {
    const char *response_body = "<html><body><h1>You connected well to the server!</h1></body></html>";
    int body_len = strlen(response_body);
    char response[512];
    snprintf(response, sizeof(response),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: text/html; charset=UTF-8\r\n"
             "Content-Length: %d\r\n"
             "\r\n%s", body_len, response_body);
    write(client_fd, response, strlen(response));
}

