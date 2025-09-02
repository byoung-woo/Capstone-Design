// ssl_handler.h
#ifndef SSL_HANDLER_H
#define SSL_HANDLER_H

#include <openssl/ssl.h>

void init_ssl();
SSL_CTX* get_ssl_context();
void cleanup_ssl();

#endif