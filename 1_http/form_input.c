#include "form_input.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAX_VAL 128

void handle_form_input(int client_fd, const char *path) {
    // 1) 쿼리 스트링 부분 추출 ('?' 이후)
    const char *q = strchr(path, '?');
    if (!q) {
        q = "";
    } else {
        q++;  // '?' 다음부터
    }

    // 2) 기본값 설정
    char name[MAX_VAL] = "Guest";
    char age[MAX_VAL]  = "N/A";
    char lang[MAX_VAL] = "en";

    // 3) 쿼리 스트링 복사 (strtok가 원본을 변경하므로)
    char qs_copy[512];
    strncpy(qs_copy, q, sizeof(qs_copy) - 1);
    qs_copy[sizeof(qs_copy) - 1] = '\0';

    // 4) key=value 단위로 분리하여 처리
    char *token = strtok(qs_copy, "&");
    while (token) {
        char key[64], val[MAX_VAL];
        // "key=value" 형태로 분리
        if (sscanf(token, "%63[^=]=%127s", key, val) == 2) {
            if (strcmp(key, "name") == 0) {
                strncpy(name, val, MAX_VAL - 1);
                name[MAX_VAL - 1] = '\0';
            } else if (strcmp(key, "age") == 0) {
                strncpy(age, val, MAX_VAL - 1);
                age[MAX_VAL - 1] = '\0';
            } else if (strcmp(key, "lang") == 0) {
                strncpy(lang, val, MAX_VAL - 1);
                lang[MAX_VAL - 1] = '\0';
            }
     
        }
        token = strtok(NULL, "&");
    }

    // 5) 응답 본문 생성
    char body[512];
    int body_len = snprintf(body, sizeof(body),
           "<!DOCTYPE html>"
	   "<html>"
	   "<head>"
	   "<meta charset=\"UTF-8\">"
	   "</head>"
	   "<body>"
           "<h1>Hello, %s!</h1>"
           "<p>Age: %s</p>"
           "<p>Language: %s</p>"
           "</body></html>",
           name, age, lang);

    // 6) 헤더 작성 및 전송
    char header[256];
    int header_len = snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Content-Length: %d\r\n"
            "\r\n", body_len);

    write(client_fd, header, header_len);
    write(client_fd, body, body_len);
}
