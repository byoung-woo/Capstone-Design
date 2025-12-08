#include <string.h>
#include <stdio.h>
#include "utils.h"

// URL 디코딩 헬퍼 함수
static int hex_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}


// URL 디코딩 함수: 문자열을 In-place로 디코딩합니다.
void url_decode(char *str) {
    char *p = str;
    char *q = str;
    while (*p) {
        if (*p == '%') {
            if (*(p + 1) && *(p + 2)) {
                *q++ = hex_to_int(*(p + 1)) * 16 + hex_to_int(*(p + 2));
                p += 3;
            } else {
                *q++ = *p++;
            }
        } else if (*p == '+') {
            *q++ = ' ';
            p++;
        } else {
            *q++ = *p++;
        }
    }
    *q = '\0';
}

// 폼 데이터에서 특정 키의 값을 안전하게 추출하고 URL 디코딩까지 수행하는 함수
char* get_form_value(const char* body, const char* key, char* output, size_t output_size) {
    if (!body || !key || !output) return NULL;

    char key_with_equals[128];
    snprintf(key_with_equals, sizeof(key_with_equals), "%s=", key);

    const char* start = strstr(body, key_with_equals);
    if (!start) return NULL;
    
    start += strlen(key_with_equals);
    
    const char* end = strchr(start, '&');
    size_t len;
    if (end) {
        len = end - start;
    } else {
        len = strlen(start);
    }

    if (len >= output_size) {
        len = output_size - 1;
    }

    strncpy(output, start, len);
    output[len] = '\0';

    url_decode(output);

    return output;
}
