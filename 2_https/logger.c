
#include "logger.h"
#include <stdio.h>

void log_request(const char *client_ip, const char *request) {
    printf("Client IP: %s\n", client_ip);
    printf("Request:\n%s\n", request);
}


