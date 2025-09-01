#ifndef SSL_INIT_H
#define SSL_INIT_H

#include <openssl/ssl.h>
#include <openssl/err.h>

/* --- 초기화 / 정리 --- */
void init_openssl(void);           /* 라이브러리 전역 초기화 */
void cleanup_openssl(void);        /* 종료 시 정리 */

/* --- 서버용 컨텍스트 --- */
SSL_CTX *create_server_context(void);
void configure_server_context(SSL_CTX *ctx,
                              const char *cert_file,
                              const char *key_file);

#endif 

